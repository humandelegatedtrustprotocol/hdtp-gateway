package node

// Outbound delivery (SPEC §7.1, PACT §6.2) — the half of messaging that did not
// exist.
//
// Both places an owner composes a message — the portal's send button and the
// owner MCP's `send_to_contact` — called `messaging.Service.Record`, which
// writes a row and returns. `internal/messaging` imports only the store; it has
// no path to the wire at all. So the portal said "delivered", the row said
// "delivered", and nothing had left the machine. Every two-node test passed
// because the tests drove `outbound.Client` themselves.
//
// The order here is deliberate: RECORD first, then deliver. A message the owner
// typed must survive a failed send — losing it would be worse than showing it as
// pending — so the local row is written before anything is attempted, and its
// status is what tells the truth about where it got to.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations/providers"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	"github.com/tech-sumit/pact-gateway/internal/public"
)

// Delivery statuses a message row can carry (SPEC §7.1).
const (
	StatusPending   = "pending"
	StatusDelivered = "delivered"
	StatusFailed    = "failed"
)

// SendMessage records an owner-composed message and delivers it to the contact.
//
// It returns the recorded result even when delivery fails: the message exists
// locally either way, and the error says what happened to it. The status on the
// row is authoritative — `pending` means written but not yet accepted.
func (n *Node) SendMessage(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error) {
	n.mu.RLock()
	acct := n.accounts[accountID]
	n.mu.RUnlock()
	if acct == nil {
		return messaging.Result{}, fmt.Errorf("send: unknown account")
	}
	c, err := n.opts.Store.GetContact(ctx, accountID, contactFpr)
	if err != nil {
		return messaging.Result{}, fmt.Errorf("send: unknown contact")
	}
	if c.Status != "active" {
		// A blocked or still-pending contact is not somebody this node writes to.
		return messaging.Result{}, fmt.Errorf("send: contact is %s, not active", c.Status)
	}

	res, err := acct.msg.Record(ctx, accountID, contactFpr, messaging.DirOut, in)
	if err != nil {
		return messaging.Result{}, err
	}
	// An idempotent replay of a msg_id already delivered must not send twice.
	if res.Status == StatusDelivered {
		return res, nil
	}

	exp := time.Now().Add(DefaultExpiry)
	if in.ExpiresAt > 0 {
		exp = time.Unix(in.ExpiresAt, 0)
	}
	// The message is RECORDED by now, so it exists whether or not the caller is
	// still waiting. Delivery is therefore the NODE's job, and must not be
	// abandoned because the caller's context ended: an owner-MCP call whose
	// session closes, a browser that navigates away after POSTing, or any
	// per-request deadline would otherwise cancel a committed send mid-flight.
	// That is exactly what happened — deliveries died with `context canceled` and
	// arrived a minute later from the retry loop, so messaging worked eventually
	// instead of working.
	//
	// WithoutCancel keeps the request's values and drops only its cancellation;
	// the budget below is what bounds this attempt.
	dctx, cancelDelivery := context.WithTimeout(context.WithoutCancel(ctx), deliveryBudget)
	defer cancelDelivery()
	derr := n.deliverWithExpiry(dctx, accountID, c, in, res.ThreadID, exp)
	if derr != nil {
		// Why it did not land, not just that it did not: a retry that succeeds
		// leaves a trail that otherwise explains nothing.
		n.auditFor(accountID, "send_message", "contact:"+contactFpr+" "+whyFailed(derr), "undelivered")
		return res, derr
	}
	status := StatusDelivered
	// Same reasoning: a delivery that succeeded must be RECORDED as delivered
	// even if the caller has gone, or the retry loop sends it a second time.
	if err := n.setStatus(context.WithoutCancel(ctx),
		accountID, contactFpr, in.MsgID, res.ThreadID, status); err != nil {
		return res, err
	}
	n.auditFor(accountID, "send_message", "contact:"+contactFpr, status)
	res.Status = status
	return res, nil
}

// SendMedia records an outbound media message and delivers it through the
// peer's `send_media`. Media goes direct only, as everything now does (PACT §9):
// there is no relay, and a 5 MiB blob would have had no business in one
// queue. Until it lands it stays pending and the retry sweep re-sends it like
// text — from the blob, not from the row, whose body is only the metadata.
func (n *Node) SendMedia(ctx context.Context, accountID, contactFpr string, in messaging.Input, filename, mime string, data []byte) (messaging.Result, error) {
	n.mu.RLock()
	acct := n.accounts[accountID]
	n.mu.RUnlock()
	if acct == nil {
		return messaging.Result{}, fmt.Errorf("send: unknown account")
	}
	c, err := n.opts.Store.GetContact(ctx, accountID, contactFpr)
	if err != nil {
		return messaging.Result{}, fmt.Errorf("send: unknown contact")
	}
	if c.Status != "active" {
		return messaging.Result{}, fmt.Errorf("send: contact is %s, not active", c.Status)
	}
	res, err := acct.media.SendInline(ctx, acct.msg, accountID, contactFpr, in, filename, mime, data)
	if err != nil {
		return messaging.Result{}, err
	}
	if res.Status == StatusDelivered {
		return res, nil
	}
	// Same reasoning as SendMessage: the row exists, so delivery is the node's
	// job and must outlive the caller's request.
	dctx, cancelDelivery := context.WithTimeout(context.WithoutCancel(ctx), deliveryBudget)
	defer cancelDelivery()
	if derr := n.deliverMedia(dctx, accountID, c, in.MsgID, res.ThreadID, string(in.Label()), filename, mime, data); derr != nil {
		n.auditFor(accountID, "send_media", "contact:"+contactFpr+" "+whyFailed(derr), "undelivered")
		return res, derr
	}
	if err := n.setStatus(context.WithoutCancel(ctx), accountID, contactFpr, in.MsgID, res.ThreadID, StatusDelivered); err != nil {
		return res, err
	}
	n.auditFor(accountID, "send_media", "contact:"+contactFpr, StatusDelivered)
	res.Status = StatusDelivered
	return res, nil
}

// deliverMedia is one direct attempt at the peer's send_media (PACT §6.2).
func (n *Node) deliverMedia(ctx context.Context, accountID string, c store.Contact, msgID, threadID, sender, filename, mime string, data []byte) error {
	peer, err := n.peerOf(accountID, c)
	if err != nil {
		return fmt.Errorf("send: media needs a direct endpoint, and that contact publishes none")
	}
	if err := checkEndpoint(peer.Endpoint, len(c.SPKI) > 0); err != nil {
		n.auditFor(c.AccountID, "delivery", "contact:"+c.Fingerprint, "endpoint_refused")
		return err
	}
	client, err := n.clientForContact(ctx, accountID, c)
	if err != nil {
		return err
	}
	args := map[string]any{
		"msg_id": msgID, "thread_id": threadID, "filename": filename, "mime": mime,
		"data": base64.StdEncoding.EncodeToString(data), "sender": sender,
	}
	res, err := client.Call(ctx, peer, c.SPKI, "send_media", args, msgID)
	if err != nil {
		return err
	}
	return refusal(res)
}

// retryMedia is the sweep's media branch: the bytes come from the blob store,
// never from the row. Reports whether the message was delivered.
func (n *Node) retryMedia(ctx context.Context, m store.Message, c store.Contact, now int64) bool {
	var meta messaging.MediaMeta
	if json.Unmarshal([]byte(m.Body), &meta) != nil || meta.Hash == "" {
		return false
	}
	n.mu.RLock()
	acct := n.accounts[m.AccountID]
	n.mu.RUnlock()
	if acct == nil {
		return false
	}
	data, err := acct.media.Blobs.Get(meta.Hash)
	if err != nil {
		return false
	}
	attempt := m.Attempts + 1
	if err := n.opts.Store.SetMessageAttempt(ctx, m.AccountID, m.ContactFpr, m.MsgID,
		attempt, now+int64(retryDelay(attempt)/time.Second)); err != nil {
		return false
	}
	if err := n.deliverMedia(ctx, m.AccountID, c, m.MsgID, m.ThreadID, m.Sender, meta.Filename, meta.Mime, data); err != nil {
		return false
	}
	if err := n.setStatus(ctx, m.AccountID, m.ContactFpr, m.MsgID, m.ThreadID, StatusDelivered); err != nil {
		return false
	}
	n.auditFor(m.AccountID, "send_media", "contact:"+m.ContactFpr+" msg:"+m.MsgID, "delivered_on_retry")
	return true
}

// deliverWithExpiry makes one attempt to reach the peer. Delivery is direct and
// only direct (PACT §9): there is no relay role, so a peer that cannot be reached
// before `expires` is a reported failure, not a message handed to a third party.
func (n *Node) deliverWithExpiry(ctx context.Context, accountID string, c store.Contact, in messaging.Input, threadID string, expiry time.Time) error {
	card, err := contacts.ParseCard(c.Card)
	if err != nil {
		return fmt.Errorf("send: that contact's card is unreadable")
	}
	// The endpoint is the leaf's (PACT §14.1), never a card property.
	peer, perr := n.peerOf(accountID, c)
	if perr != nil {
		return perr
	}
	card.Endpoint = peer.Endpoint
	if card.Endpoint == "" {
		return fmt.Errorf("send: that contact publishes no endpoint")
	}
	if err := checkEndpoint(card.Endpoint, len(c.SPKI) > 0); err != nil {
		n.auditFor(c.AccountID, "delivery", "contact:"+c.Fingerprint, "endpoint_refused")
		return err
	}
	client, err := n.clientForContact(ctx, accountID, c)
	if err != nil {
		return err
	}
	args := map[string]any{
		"msg_id": in.MsgID, "text": in.Text, "thread_id": threadID,
		"sender": string(in.Label()),
	}
	if in.Topic != "" {
		args["topic"] = in.Topic
	}
	if in.ReplyTo != "" {
		args["reply_to"] = in.ReplyTo
	}
	// The peer's card decides whether this is sealed; Client.Call owns that rule so
	// every outbound path obeys the same one.
	res, derr := client.Call(ctx, peer, c.SPKI, "send_message", args, in.MsgID)
	if derr != nil {
		return derr
	}
	return refusal(res)
}

// refusal turns a peer's error result into an error. A peer that refuses is not
// a transport failure: it is an answer, and it must not read as delivered.
func refusal(res *mcp.CallToolResult) error {
	if res == nil || !res.IsError {
		return nil
	}
	body := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			body = tc.Text
		}
	}
	var code struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal([]byte(body), &code)
	if code.Code != "" {
		return fmt.Errorf("send: the contact's node refused: %s", code.Code)
	}
	return fmt.Errorf("send: the contact's node refused")
}

/* ---------------------------- retry (SPEC §7.1) ---------------------------- */

// deliveryBudget bounds one delivery attempt made on a caller's behalf. It is
// generous next to a healthy round trip (about a second through a tunnel) and far
// short of anything a person would wait through: past it the message is already
// recorded and the retry loop owns it.
const deliveryBudget = 30 * time.Second

// DefaultExpiry is PACT §7's outbound deadline: retries stop after 24 hours.
const DefaultExpiry = 24 * time.Hour

// RetrySweep is the interval between passes over undelivered outbound messages.
// The pass itself is cheap — a bounded query that usually returns nothing — and
// backoffDue, not this, decides how often any given message is actually retried.
const RetrySweep = 15 * time.Second

// MaxRetryBatch bounds one pass, so a large backlog cannot monopolise a tick.
const MaxRetryBatch = 128

// expiryOf reads a message's deadline, applying the default when unset.
func expiryOf(m store.Message) int64 {
	if m.ExpiresAt > 0 {
		return m.ExpiresAt
	}
	return m.CreatedAt + int64(DefaultExpiry/time.Second)
}

// MaxRetryDelay caps the gap between attempts, so a long-lived message still
// gets a regular chance before its deadline.
const MaxRetryDelay = 30 * time.Minute

// retryDelay is how long to wait after `attempts` failed attempts. It doubles
// from one sweep interval up to the cap.
//
// Backoff is a function of attempts MADE, deliberately. Deriving it from the
// message's age instead (age%1800 < 15) meant a retry happened only when a
// sweep's wall-clock second landed inside a 15-second window — and sweeps are
// not evenly spaced, because one sweep does network I/O with timeouts for up to
// MaxRetryBatch messages. Every window a slow sweep stepped over cost the
// message another half hour.
func retryDelay(attempts int64) time.Duration {
	d := RetrySweep
	for i := int64(1); i < attempts && d < MaxRetryDelay; i++ {
		d *= 2
	}
	if d > MaxRetryDelay {
		return MaxRetryDelay
	}
	return d
}

// retryDue reports whether this message's next attempt is due. A row that has
// never been scheduled (next_attempt_at = 0, including every row written before
// this column existed) is due immediately.
func retryDue(m store.Message, now int64) bool { return now >= m.NextAttemptAt }

// RetryPending re-attempts undelivered outbound messages and reports how many it
// delivered and how many it gave up on.
//
// SPEC §7.1: "retries with backoff until the sender-chosen `expires`… The same
// `msg_id` MUST be reused across every retry", which is what makes this safe —
// the recipient's idempotency handling (§7.2) turns a duplicate into the
// original acknowledgment rather than a second message.
func (n *Node) RetryPending(ctx context.Context) (delivered, expired int) {
	now := time.Now().Unix()
	if n.opts.Now != nil {
		now = n.opts.Now().Unix()
	}
	pending, err := n.opts.Store.ListPendingOutbound(ctx, MaxRetryBatch)
	if err != nil {
		return 0, 0
	}
	for _, m := range pending {
		expiredNow := now >= expiryOf(m)
		if expiredNow {
			// Nothing carried it. Say so on the row: an owner is owed the truth
			// that this one never arrived.
			if err := n.setStatus(ctx, m.AccountID, m.ContactFpr, m.MsgID, m.ThreadID, StatusFailed); err == nil {
				n.auditFor(m.AccountID, "send_message", "contact:"+m.ContactFpr+" msg:"+m.MsgID, "expired")
				expired++
			}
			continue
		}
		if !retryDue(m, now) {
			continue
		}
		c, err := n.opts.Store.GetContact(ctx, m.AccountID, m.ContactFpr)
		if err != nil || c.Status != "active" {
			continue
		}
		if m.Kind == "media" {
			// A media row's body is metadata; sending it as text would deliver
			// a JSON blob as a message. The bytes are in the blob store.
			if n.retryMedia(ctx, m, c, now) {
				delivered++
			}
			continue
		}
		in := messaging.Input{
			MsgID: m.MsgID, ThreadID: m.ThreadID, Text: m.Body,
			ReplyTo: m.ReplyTo, Sender: messaging.Sender(m.Sender), Origin: messaging.OriginStored,
		}
		// Record the attempt BEFORE trying, so a delivery that panics or a
		// process that dies mid-send cannot leave the row due on every sweep.
		attempt := m.Attempts + 1
		if err := n.opts.Store.SetMessageAttempt(ctx, m.AccountID, m.ContactFpr, m.MsgID,
			attempt, now+int64(retryDelay(attempt)/time.Second)); err != nil {
			continue
		}
		if err := n.deliverWithExpiry(ctx, m.AccountID, c, in, m.ThreadID,
			time.Unix(expiryOf(m), 0)); err != nil {
			continue // still unreachable; the next scheduled attempt tries again
		}
		status, detail := StatusDelivered, "delivered_on_retry"
		if err := n.setStatus(ctx, m.AccountID, m.ContactFpr, m.MsgID, m.ThreadID, status); err == nil {
			n.auditFor(m.AccountID, "send_message", "contact:"+m.ContactFpr+" msg:"+m.MsgID, detail)
			delivered++
		}
	}
	return delivered, expired
}

// setStatus records an outbound message's new delivery status and announces it.
//
// Every status write went straight to the store, so a conversation open in the
// portal kept showing "not delivered yet — retrying" for a message that had
// since arrived: the page had nothing to learn from. It only looked right after
// a manual reload, which is the owner doing the node's job.
func (n *Node) setStatus(ctx context.Context, accountID, contactFpr, msgID, threadID, status string) error {
	if err := n.opts.Store.SetMessageStatus(ctx, accountID, contactFpr, msgID, status); err != nil {
		return err
	}
	if n.opts.Bus != nil {
		n.opts.Bus.Publish(messaging.Event{
			Kind: messaging.EventDelivery, AccountID: accountID,
			ContactFpr: contactFpr, ThreadID: threadID, Status: status,
		})
	}
	return nil
}

func whyFailed(err error) string {
	if err == nil {
		return "why:unknown"
	}
	// Redact BEFORE truncating: a secret cut in half is still a secret's prefix.
	msg := core.Redact(err.Error())
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return "why:" + msg
}

// RunRetries sweeps until ctx ends. This is the piece that makes a failed send
// recoverable rather than a message the owner has to notice and resend.
func (n *Node) RunRetries(ctx context.Context) {
	t := time.NewTicker(RetrySweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.RetryPending(ctx)
		}
	}
}

func (n *Node) FetchMedia(ctx context.Context, accountID, rawURL string) (string, error) {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil || a.media == nil {
		return "", fmt.Errorf("media: unknown account")
	}
	return a.media.Fetch(ctx, accountID, rawURL)
}

// InvalidateAccount reconciles every cached caller on an account, on every
// account when accountID is "". An exposure change or a withheld integration
// alters what is served to everybody, not to one caller (SPEC §6.5, §6.10).
func (n *Node) InvalidateAccount(ctx context.Context, accountID string) {
	n.mu.RLock()
	ids := make([]string, 0, len(n.accounts))
	for id := range n.accounts {
		if accountID == "" || id == accountID {
			ids = append(ids, id)
		}
	}
	n.mu.RUnlock()
	for _, id := range ids {
		if p := n.Pool(id); p != nil {
			p.InvalidateAll(ctx, id)
		}
	}
}

/* ------------------- capability resolution (SPEC §6.7, E5) ------------------- */

// calendarAt and statusAt resolve an account's provider at CALL time rather than
// when the account was built. The maps in Options are a snapshot: an integration
// connected, withheld or restored after composition could never appear through
// them, which is exactly the lifecycle §6.10 describes.
type calendarAt struct {
	n         *Node
	accountID string
}

type statusAt struct {
	n         *Node
	accountID string
}

// errNoCalendar is what a node with no calendar provider answers. The tool layer
// turns it into `unavailable` (SPEC §6.10).
var errNoCalendar = errors.New("node: no calendar provider is configured")

func (c calendarAt) resolve() public.Calendar {
	if c.n.opts.Capabilities != nil {
		if cal, _ := c.n.opts.Capabilities(c.accountID); cal != nil {
			return cal
		}
	}
	return c.n.opts.Calendar[c.accountID]
}

func (c calendarAt) CheckAvailability(ctx context.Context, from, to time.Time, d time.Duration) ([]providers.Slot, error) {
	cal := c.resolve()
	if cal == nil {
		return nil, errNoCalendar
	}
	return cal.CheckAvailability(ctx, from, to, d)
}

func (c calendarAt) BookSlot(ctx context.Context, contactFpr, msgID string, slot providers.Slot, subject string) (providers.BookingAck, error) {
	cal := c.resolve()
	if cal == nil {
		return providers.BookingAck{}, errNoCalendar
	}
	return cal.BookSlot(ctx, contactFpr, msgID, slot, subject)
}

func (c calendarAt) CancelBooking(ctx context.Context, bookingID string) error {
	cal := c.resolve()
	if cal == nil {
		return errNoCalendar
	}
	return cal.CancelBooking(ctx, bookingID)
}

// GetStatus answers §6.7's default: a node with no status recipe is available.
// It used to answer `unavailable` on every node forever, because the Status map
// was never populated — so PACT's simplest capability never worked at all.
func (s statusAt) GetStatus(ctx context.Context) (string, error) {
	if s.n.opts.Capabilities != nil {
		if _, st := s.n.opts.Capabilities(s.accountID); st != nil {
			return st.GetStatus(ctx)
		}
	}
	if st := s.n.opts.Status[s.accountID]; st != nil {
		return st.GetStatus(ctx)
	}
	return "available", nil
}

// SetIntegrationTools replaces the tools one integration serves on an account
// and rebuilds every affected caller, so the change reaches sessions that are
// already open (SPEC §6.5, §6.10). Passing no entries withdraws the integration
// — which is what a withhold, or an exposure set the owner emptied, means.
func (n *Node) SetIntegrationTools(ctx context.Context, accountID, integrationID string, entries []public.Entry) {
	n.mu.RLock()
	a := n.accounts[accountID]
	n.mu.RUnlock()
	if a == nil || a.reg == nil {
		return
	}
	a.reg.Replace("integration:"+integrationID, entries)
	n.InvalidateAccount(ctx, accountID)
}

/* ------------------ where a contact's card may point us ------------------ */

// checkEndpoint refuses a peer endpoint that would send this node somewhere it
// must not go (SPEC §7.5's reasoning, applied to the outbound leg).
//
// A contact controls this value: `update_contact` verifies a signature over the
// new FINGERPRINT, not over the card body, and explicitly supports an unchanged
// fingerprint as "an endpoint change" — so an active contact can repoint us at
// will. Two rules follow.
//
// `https` is required unconditionally, because the pinned-key check lives in the
// TLS handshake's VerifyPeerCertificate: over `http` there is no handshake, so
// the pin does not merely weaken — it does not run at all, and the message goes
// out in cleartext to whatever answered.
//
// A private address is refused only when NO key is pinned. That distinction is
// the whole point: with a pinned key the handshake already decides who may
// answer, so dialing 192.168.1.5 reaches that contact or nobody — it is not a
// server-side request primitive, and refusing it would break the local and
// same-LAN deployments this project is built for. With only a fingerprint (a
// contact mid-rotation, §3.9) the pin cannot run either, and then an
// attacker-chosen loopback or RFC 1918 address is exactly the primitive §7.5
// denies on the inbound side, for the same reason.
func checkEndpoint(raw string, pinned bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("send: that contact's endpoint is unreadable")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("send: refusing a %q endpoint — only https carries the "+
			"pinned-key check that makes a peer's identity mean anything", u.Scheme)
	}
	if pinned {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && messaging.IsPrivateAddr(ip) {
		return fmt.Errorf("send: refusing to dial the private address %s on a card "+
			"whose key is not pinned — nothing would verify what answered", ip)
	}
	return nil
}

// The owner's agent is not always connected, and a notification it can miss is
// not a notification. SPEC §7.8's bus already pushes `ResourceUpdated` to
// SUBSCRIBED sessions, which serves an agent that happens to be attached and
// nothing else: an agent that reconnects has no way to ask what changed while
// it was away, and the bus is explicitly "a hint, not the ledger".
//
// These two tools are the agent's side of that. `wait_for_updates` blocks until
// something happens (or the timeout elapses) and answers with what changed since
// the caller's cursor, so a loop is one call and a restart loses nothing.
// `digest` answers the end-of-day question — what arrived, from whom, and what
// is still unanswered — in a single call rather than a walk over every thread.
//
// Neither decides anything. What to do about a message — reply, escalate to the
// human, or leave it for the digest — is the agent's judgment, and putting that
// policy in the node would be a second, worse agent (SPEC §7.7: the node labels
// and hands over; it does not act on a contact's words).
package ownermcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// WaitArgs is a resumable cursor and a bound on how long to hold the call.
type WaitArgs struct {
	AccountID string `json:"account_id"`
	// SinceTS is the cursor from a previous answer. Omit it to start watching
	// from now: the first call returns immediately with a cursor and no
	// backlog, so an agent can begin a loop without replaying its history.
	SinceTS int64 `json:"since_ts,omitempty" jsonschema:"cursor from a previous wait_for_updates; omit to start from now"`
	// TimeoutSec bounds the wait: whole seconds from 1 to WaitMaxSec, WaitMaxSec
	// when omitted. A pointer, so an omitted bound (the default) and an explicit 0
	// (refused: it would answer at once, and a loop on it spins) are told apart.
	TimeoutSec *int64 `json:"timeout_sec,omitempty" jsonschema:"seconds to wait for something to happen, from 1 to 25; 25 when omitted"`
}

// WaitMaxSec is the longest wait_for_updates holds a call, and its default: the
// hosted edition's bound too (pact-cloud WATCH_WAIT_MAX_SEC, its /v1 watchChanges
// and its owner MCP's wait), so an agent written for one host waits the same on
// the other. Under half a minute, so a proxy's or a platform's idle timeout does
// not cut a call mid-wait.
const WaitMaxSec = 25

type DigestArgs struct {
	AccountID string `json:"account_id"`
	// SinceTS bounds the window; omit for the last 24 hours.
	SinceTS int64 `json:"since_ts,omitempty" jsonschema:"unix seconds; omit for the last 24 hours"`
}

// changed is one thread that moved, with enough to decide whether to look
// closer. The bodies are deliberately not here: they are untrusted text and the
// agent should read them through read_thread, which labels every one with the
// contact's trust flag (§7.7).
type changed struct {
	ThreadID   string `json:"thread_id"`
	ContactFpr string `json:"contact_fpr"`
	Contact    string `json:"contact,omitempty"`
	Unread     int64  `json:"unread"`
	LastAt     int64  `json:"last_at"`
	// Trust is the OWNER's stance on this contact (§7.6), carried here so the
	// agent can triage without a read: may_instruct threads may be acted on,
	// messages_only threads are raised to the human. The label is resolved
	// from the owner's row — nothing the contact sent can influence it.
	Trust string `json:"trust,omitempty"`
}

// callEvent is one substantive tool call a contact made against this account
// since the cursor — a booking, a media send, an availability check. Sourced
// from the audit trail, so it is exactly what the node recorded, and it names
// only the caller and the tool: arguments are the peer's untrusted input and
// stay behind read_thread / the audit page.
type callEvent struct {
	ContactFpr string `json:"contact_fpr"`
	Tool       string `json:"tool"`
	Trust      string `json:"trust,omitempty"`
	At         int64  `json:"at"`
}

// attention is a condition only the owner can clear.
type attention struct {
	Kind        string `json:"kind"` // integration_auth
	Integration string `json:"integration"`
	Status      string `json:"status"`
}

type waitResult struct {
	// Cursor to pass as since_ts next time. It advances even when nothing
	// changed, so a quiet loop does not re-read the same tail forever.
	Cursor int64 `json:"cursor"`
	// Threads that moved since the cursor.
	Threads []changed `json:"threads"`
	// Waiting is the count of contact requests awaiting the owner's approval,
	// and Pending the agent-answered calls waiting for an answer (§6.8). Both
	// are things only a person or their agent can clear, so a watcher that
	// only looked at messages would sit next to a blocked contact forever.
	Waiting int64 `json:"contact_requests"`
	Pending int64 `json:"pending_requests"`
	// Addresses is the count of contacts waiting at a new address for the owner's answer (PACT
	// §5.3, list_pending_addresses): a third queue only the owner clears, and parking one wakes
	// this wait the way a contact request does.
	Addresses int64 `json:"pending_addresses"`
	// Calls: substantive tool calls contacts made since the cursor (bookings,
	// media, availability), so an agent learns a peer ACTED, not only that a
	// message arrived.
	Calls []callEvent `json:"calls,omitempty"`
	// NeedsAttention: conditions only the owner can clear — today, an
	// integration whose token died (auth_error) and needs re-authorizing.
	NeedsAttention []attention `json:"needs_attention,omitempty"`
	// CallsTruncated says the audit window scrolled past this cursor: there
	// were more rows since since_ts than one read returns, so Calls may be
	// missing older events. The full trail is audit_query's job.
	CallsTruncated bool `json:"calls_truncated,omitempty"`
	// TimedOut says the wait ended on the clock rather than on an event: the
	// difference between "nothing happened" and "here is what happened".
	TimedOut bool `json:"timed_out"`
}

// AddWatchTools registers the agent's change feed and its digest.
func AddWatchTools(s *mcp.Server, d Deps, allow func(ctx context.Context, accountID string) bool) {
	ot := ownerTools{d: d, allow: allow}
	mcp.AddTool(s, &mcp.Tool{
		Name: "wait_for_updates",
		Description: "Block until something changes for this account — a message arrives, a contact asks to connect, " +
			"a request needs answering — then return what moved since your cursor. Call it in a loop with the cursor " +
			"it returns. Omitting since_ts starts from now with no backlog.",
	}, ot.waitForUpdatesTool)

	mcp.AddTool(s, &mcp.Tool{
		Name: "digest",
		Description: "What happened in a window and what is still open: messages in and out per contact, who is " +
			"waiting on a reply, contacts asking to connect, requests awaiting an answer. For an end-of-day summary.",
	}, ot.digestTool)
}

// waitForUpdatesTool is the `wait_for_updates` tool.
func (ot ownerTools) waitForUpdatesTool(ctx context.Context, req *mcp.CallToolRequest, a WaitArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	timeout := WaitMaxSec * time.Second
	if a.TimeoutSec != nil {
		if *a.TimeoutSec < 1 || *a.TimeoutSec > WaitMaxSec {
			b, err := json.Marshal(map[string]string{"code": "bad_request", "detail": fmt.Sprintf("timeout_sec is whole seconds from 1 to %d", WaitMaxSec)})
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
		}
		timeout = time.Duration(*a.TimeoutSec) * time.Second
	}
	// A first call has nothing to say: hand back a cursor and let the next
	// call do the waiting. Replaying every thread on connect would make the
	// agent's first act a re-read of its whole history.
	if a.SinceTS == 0 {
		r, err := jsonResult(waitResult{Cursor: time.Now().Unix()})
		return r, nil, err
	}
	res, err := ot.d.changesSince(ctx, a.AccountID, a.SinceTS)
	if err != nil {
		return nil, nil, err
	}
	if len(res.Threads) > 0 || res.Waiting > 0 || res.Pending > 0 {
		r, err := jsonResult(res)
		return r, nil, err
	}
	// Nothing yet: wait for the bus to say otherwise. The store, not the
	// event, is what answers — an event can be dropped when a subscriber is
	// full (§7.8), and re-reading is always correct.
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var ch <-chan any
	if ot.d.Bus != nil {
		evs, stop := ot.d.Bus.Subscribe(a.AccountID)
		defer stop()
		c := make(chan any, 1)
		go func() {
			select {
			case <-evs:
				c <- struct{}{}
			case <-wctx.Done():
			}
		}()
		ch = c
	}
	select {
	case <-ch:
	case <-wctx.Done():
		res.Cursor = time.Now().Unix()
		res.TimedOut = true
		r, err := jsonResult(res)
		return r, nil, err
	}
	after, err := ot.d.changesSince(ctx, a.AccountID, a.SinceTS)
	if err != nil {
		return nil, nil, err
	}
	r, err := jsonResult(after)
	return r, nil, err
}

// digestTool is the `digest` tool.
func (ot ownerTools) digestTool(ctx context.Context, req *mcp.CallToolRequest, a DigestArgs) (*mcp.CallToolResult, any, error) {
	if !ot.allow(ctx, a.AccountID) {
		r, err := deny()
		return r, nil, err
	}
	since := a.SinceTS
	if since == 0 {
		since = time.Now().Add(-24 * time.Hour).Unix()
	}
	threads, err := ot.d.Store.ListThreadsByAccount(ctx, a.AccountID)
	if err != nil {
		return nil, nil, err
	}
	type perContact struct {
		ContactFpr    string `json:"contact_fpr"`
		Contact       string `json:"contact,omitempty"`
		In            int    `json:"in"`
		Out           int    `json:"out"`
		Unread        int64  `json:"unread"`
		LastAt        int64  `json:"last_at"`
		LastDirection string `json:"last_direction,omitempty"`
		// AwaitingReply: their last word came after ours. The agent decides
		// what that is worth; the digest only says it is true.
		AwaitingReply bool   `json:"awaiting_reply"`
		Trust         string `json:"trust,omitempty"`
	}
	by := map[string]*perContact{}
	for _, th := range threads {
		msgs, err := ot.d.Store.ListMessagesByThread(ctx, a.AccountID, th.ID)
		if err != nil {
			continue
		}
		p := by[th.ContactFpr]
		if p == nil {
			p = &perContact{ContactFpr: th.ContactFpr}
			if c, err := ot.d.Store.GetContact(ctx, a.AccountID, th.ContactFpr); err == nil {
				p.Contact = displayName(c)
				p.Trust = c.TrustFlag
			}
			by[th.ContactFpr] = p
		}
		if n, err := ot.d.Store.UnreadCount(ctx, a.AccountID, th.ID); err == nil {
			p.Unread += n
		}
		for _, m := range msgs {
			if m.CreatedAt < since {
				continue
			}
			if m.Direction == "in" {
				p.In++
			} else {
				p.Out++
			}
			if m.CreatedAt >= p.LastAt {
				p.LastAt, p.LastDirection = m.CreatedAt, m.Direction
			}
		}
	}
	out := make([]perContact, 0, len(by))
	for _, p := range by {
		p.AwaitingReply = p.LastDirection == "in"
		if p.In > 0 || p.Out > 0 || p.Unread > 0 {
			out = append(out, *p)
		}
	}
	waiting, addresses, pending := ot.d.openCounts(ctx, a.AccountID)
	r, err := jsonResult(map[string]any{
		"since": since, "until": time.Now().Unix(), "contacts": out,
		"contact_requests": waiting, "pending_addresses": addresses, "pending_requests": pending,
	})
	return r, nil, err
}

// changesSince is the shared read behind the wait: threads that moved, and the
// two queues only a person can clear.
func (d Deps) changesSince(ctx context.Context, accountID string, since int64) (waitResult, error) {
	threads, err := d.Store.ListThreadsByAccount(ctx, accountID)
	if err != nil {
		return waitResult{}, err
	}
	res := waitResult{Cursor: since}
	for _, th := range threads {
		if th.LastAt <= since {
			continue
		}
		c := changed{ThreadID: th.ID, ContactFpr: th.ContactFpr, LastAt: th.LastAt}
		if n, err := d.Store.UnreadCount(ctx, accountID, th.ID); err == nil {
			c.Unread = n
		}
		// Fail SAFE on the label: a thread whose contact row cannot be read
		// (removed since, store hiccup) is reported at the lowest grant, the
		// same default read_thread resolves to — never unlabeled, never up.
		c.Trust = "messages_only"
		if ct, err := d.Store.GetContact(ctx, accountID, th.ContactFpr); err == nil {
			c.Contact = displayName(ct)
			c.Trust = ct.TrustFlag
		}
		res.Threads = append(res.Threads, c)
		if th.LastAt > res.Cursor {
			res.Cursor = th.LastAt
		}
	}
	res.Waiting, res.Addresses, res.Pending = d.openCounts(ctx, accountID)
	res.Calls, res.CallsTruncated = d.callsSince(ctx, accountID, since)
	for _, c := range res.Calls {
		if c.At > res.Cursor {
			res.Cursor = c.At
		}
	}
	res.NeedsAttention = d.needsAttention(ctx, accountID)
	return res, nil
}

// callActions are the peer-tool audit actions that mean "a contact ACTED", as
// opposed to messages (threads carry those) and plumbing reads. The sealed
// wrapper's own row (`sealed_call`) is deliberately NOT here: it says only
// that an envelope opened — the INNER tool writes its own attributed row, and
// that row is the one that counts. Trusting the wrapper surfaced denied inner
// calls as actions, promoted sealed messages into "calls", and counted every
// sealed booking twice.
var callActions = map[string]bool{
	"book_slot": true, "cancel_booking": true, "check_availability": true,
	"send_media": true, "get_status": true,
}

func (d Deps) callsSince(ctx context.Context, accountID string, since int64) ([]callEvent, bool) {
	const page = 500
	rows, err := d.Store.ListAuditEventsPage(ctx, store.AuditPage{Account: accountID, Limit: page})
	if err != nil {
		return nil, false
	}
	// A full page whose oldest row is still newer than the cursor means the
	// window has scrolled past events this read cannot see. Say so instead of
	// silently advancing the cursor over them — the full trail stays in
	// audit_query.
	truncated := len(rows) == page && rows[len(rows)-1].TS > since
	trustOf := map[string]string{}
	var out []callEvent
	for _, r := range rows { // newest first
		if r.TS <= since {
			break
		}
		if !callActions[r.Action] || (r.Outcome != "ok" && r.Outcome != "delivered") {
			continue
		}
		// The per-account audit page carries the node's own unattributed rows
		// too; a call event must belong to THIS account to be its feed's news.
		if r.AccountID != accountID {
			continue
		}
		fpr := ""
		for _, f := range strings.Fields(r.Resource) {
			if v, found := strings.CutPrefix(f, "caller:"); found && v != "" {
				fpr = v
			}
			if v, found := strings.CutPrefix(f, "contact:"); found && fpr == "" {
				fpr = v
			}
		}
		if fpr == "" {
			continue
		}
		trust, cached := trustOf[fpr]
		if !cached {
			if c, err := d.Store.GetContact(ctx, accountID, fpr); err == nil {
				trust = c.TrustFlag
			}
			trustOf[fpr] = trust
		}
		if trust == "" {
			// Not a contact this account knows (removed since, or a row that
			// slipped attribution): there is no owner grant to report under,
			// so the event is not this feed's news. It stays in audit_query.
			continue
		}
		out = append(out, callEvent{ContactFpr: fpr, Tool: r.Action, Trust: trust, At: r.TS})
	}
	// oldest first, the order an agent replays in
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, truncated
}

func (d Deps) needsAttention(ctx context.Context, accountID string) []attention {
	ints, err := d.Store.ListIntegrations(ctx, accountID)
	if err != nil {
		return nil
	}
	var out []attention
	for _, in := range ints {
		if in.Status == "auth_error" {
			out = append(out, attention{Kind: "integration_auth", Integration: in.Slug, Status: in.Status})
		}
	}
	return out
}

func (d Deps) openCounts(ctx context.Context, accountID string) (waiting, addresses, pending int64) {
	if cs, err := d.Store.ListContacts(ctx, accountID); err == nil {
		for _, c := range cs {
			if c.Status == "pending_in" {
				waiting++
			}
		}
	}
	if ps, err := d.Store.ListPendingAddresses(ctx, accountID); err == nil {
		addresses = int64(len(ps))
	}
	if d.Pending != nil {
		if rows, err := d.Store.ListOpenPendingRequests(ctx, accountID, time.Now().Unix()); err == nil {
			pending = int64(len(rows))
		}
	}
	return waiting, addresses, pending
}

func displayName(c store.Contact) string {
	if c.Petname != "" {
		return c.Petname
	}
	return c.DisplayName
}

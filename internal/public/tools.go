package public

// The built-in tool set of PACT §6.2 (SPEC §5.6: "built-in tools ... execute
// against the node's own store"). This file is the ONLY place those tools are
// defined; the registry, the pool and `policy.Allow` decide who sees which.
//
// Three rules hold for every handler here:
//
//   - Caller identity is the RESOLVED one — `CallerFromContext` for a pinned
//     contact, `CallerSPKI` for the key a guest proved this call (envelope
//     `spk` or client certificate). No handler reads an identity out of its
//     arguments.
//   - Untrusted strings are capped at the boundary and REFUSED when over, never
//     silently truncated, and never concatenated into an instruction.
//   - Every call answers with a PACT §12 code on failure, and audits.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/integrations/providers"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

// Boundary caps (PACT §12, SPEC §5.7). The store enforces them again.
const (
	MaxTextBytes  = 16 * 1024
	MaxNoteBytes  = 1024
	MaxInlineData = 5 * 1024 * 1024
	MaxFieldBytes = 1024 // filename, mime, subject, topic, reason, booking_id
)

// Calendar is the calendar capability as the public surface needs it — the
// three PACT tools, nothing else. `*providers.Calendar` satisfies it.
type Calendar interface {
	CheckAvailability(ctx context.Context, from, to time.Time, d time.Duration) ([]providers.Slot, error)
	BookSlot(ctx context.Context, contactFpr, msgID string, slot providers.Slot, subject string) (providers.BookingAck, error)
	CancelBooking(ctx context.Context, bookingID string) error
}

// Slot is the wire shape PACT §6.2 gives a candidate interval: RFC 3339
// instants plus the IANA zone they are rendered in. The provider works in
// time.Time; this boundary is where the zone is chosen and stated.
type Slot struct {
	Start string `json:"start"`
	End   string `json:"end"`
	TZ    string `json:"tz"`
}

// zoneOf resolves a caller-supplied IANA zone, falling back to UTC. An
// unparseable zone is not an error: the answer is simply given in UTC.
func zoneOf(tz string) *time.Location {
	if tz == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

func wireSlots(in []providers.Slot, loc *time.Location) []Slot {
	out := make([]Slot, 0, len(in))
	for _, s := range in {
		out = append(out, Slot{
			Start: s.Start.In(loc).Format(time.RFC3339),
			End:   s.End.In(loc).Format(time.RFC3339),
			TZ:    loc.String(),
		})
	}
	return out
}

// StatusSource answers `get_status`. `*providers.Status` satisfies it.
type StatusSource interface {
	GetStatus(ctx context.Context) (string, error)
}

// CardFn returns this account's current SIGNED card, the signature over it, and
// the key it names. PACT §4 says redemption returns the issuer's signed card;
// this surface used to return the raw key instead, so the same card went out
// signed over the invite landing page and unsigned over MCP. The key travels too
// because a card carries only its hash, and a guest sealing toward a
// `seal: required` issuer needs the key itself (§13).
type CardFn func(ctx context.Context) (card, sig string, spki []byte, err error)

// ToolDeps is everything the built-in set touches. A nil capability is not an
// error: its tools answer `unavailable` (PACT §12's code for a capability the
// implementation is currently withholding).
type ToolDeps struct {
	AccountID string
	Contacts  *contacts.Manager
	Messages  *messaging.Service
	Media     *messaging.MediaService
	Calendar  Calendar
	Status    StatusSource
	Card      CardFn
	// Invalidate drops a caller's cached MCP server after its tier changes.
	Invalidate func(ctx context.Context, accountID, fpr string) error
	Audit      AuditFn
	// Limits reports the boundary caps in force, for get_card's metadata; nil
	// means the compiled-in defaults. A function, not a snapshot, because the
	// rate budgets are owner knobs that change while the node serves.
	Limits func() Limits
	// Endpoint is this account's own address, for the guard a 2.0 guest's card
	// must pass (PACT §3: never the receiver's own). nil means unknown.
	Endpoint func() string
}

// proofOf is what the caller proved this call, for the guest tools to pin: in
// 1.x the key (envelope `spk` or client certificate), in 2.0 the root, the
// leaf's key, the endpoint and the leaf the chain carried (PACT §14.2 rule 6).
func (d ToolDeps) proofOf(ctx context.Context) contacts.Proof {
	if f := EnvelopeFactsFrom(ctx); f != nil && f.Protocol == 2 {
		p := contacts.Proof{Fingerprint: f.From, SPKI: f.SPKI, Protocol: 2, Endpoint: f.Endpoint, Leaf: f.Leaf}
		if d.Endpoint != nil {
			p.SelfEndpoint = d.Endpoint()
		}
		return p
	}
	tf := FactsFrom(ctx)
	if tf.ClientProtocol == 2 {
		p := contacts.Proof{Fingerprint: tf.ClientCertFingerprint, SPKI: tf.ClientCertSPKI, Protocol: 2, Endpoint: tf.ClientEndpoint, Leaf: tf.ClientLeaf}
		if d.Endpoint != nil {
			p.SelfEndpoint = d.Endpoint()
		}
		return p
	}
	spki := CallerSPKI(ctx)
	return contacts.Proof{Fingerprint: fingerprintOfSPKI(spki), SPKI: spki, Protocol: 1}
}

// audit records one boundary event. The outcome is a verdict and nothing else:
// it is what the portal colours, counts and filters by, so a caller fingerprint
// or a failure sentence in that column turns every row into its own category.
// Those belong in the resource, which is the free-text locator (SPEC §11.5).
func (d ToolDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

func (d ToolDeps) invalidate(ctx context.Context, fpr string) {
	if d.Invalidate != nil && fpr != "" {
		_ = d.Invalidate(ctx, d.AccountID, fpr)
	}
}

// fingerprintOfSPKI is the PACT §2 identity of a presented key: "sha256:" +
// base64url(SHA-256(SPKI)). An absent key has no identity, not a fake one.
func fingerprintOfSPKI(spki []byte) string {
	if len(spki) == 0 {
		return ""
	}
	sum := sha256.Sum256(spki)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

/* ------------------------------- results -------------------------------- */

func toolErr(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + code + `"}`}}}
}

func toolOK(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return toolErr("unavailable"), nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
}

// domainCode maps a domain error to its PACT §12 code. The sentinels carry the
// code as their message, so a new sentinel does not silently become `unavailable`.
func domainCode(err error) string {
	switch {
	case errors.Is(err, contacts.ErrInviteInvalid):
		return "invite_invalid"
	case errors.Is(err, contacts.ErrIdentityRequired):
		return "identity_required"
	case errors.Is(err, contacts.ErrUnknownContact):
		return "unknown_contact"
	case errors.Is(err, contacts.ErrBadRequest), errors.Is(err, messaging.ErrBadRequest):
		return "bad_request"
	case errors.Is(err, messaging.ErrTooLarge):
		return "too_large"
	default:
		return "unavailable"
	}
}

/* ------------------------------ arguments ------------------------------- */

// decode parses arguments strictly: an unparseable body is `bad_request`, not a
// zero-valued struct silently accepted.
func decode(req *mcp.CallToolRequest, v any) bool {
	if len(req.Params.Arguments) == 0 {
		return true
	}
	return json.Unmarshal(req.Params.Arguments, v) == nil
}

// capped reports whether a field is within its cap.
func capped(s string, max int) bool { return len(s) <= max }

func objSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }

func tool(name, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc, InputSchema: objSchema()}
}

// callerFpr is the resolved caller's fingerprint — never an argument.
func callerFpr(ctx context.Context) string {
	if c, ok := CallerFromContext(ctx); ok {
		return c.Fingerprint
	}
	if f := EnvelopeFactsFrom(ctx); f != nil {
		return f.From
	}
	return FactsFrom(ctx).ClientCertFingerprint
}

/* ------------------------------- the set -------------------------------- */

// BuiltinEntries returns the PACT §6.2 core tools for one account, each tagged
// with the tier and permission that gate it (SPEC §5.4).
func BuiltinEntries(d ToolDeps) []Entry {
	guest := func(name, desc string, h mcp.ToolHandler) Entry {
		return Entry{Tool: tool(name, desc), Rule: policy.Rule{Tier: policy.TierGuest}, Handler: h}
	}
	pending := func(name, desc string, h mcp.ToolHandler) Entry {
		return Entry{Tool: tool(name, desc), Rule: policy.Rule{Tier: policy.TierPending}, Handler: h}
	}
	contact := func(name, perm, desc string, h mcp.ToolHandler) Entry {
		return Entry{Tool: tool(name, desc), Rule: policy.Rule{Tier: policy.TierContact, Permission: perm}, Handler: h}
	}
	return []Entry{
		guest("redeem_invite", "Redeem an invite token and exchange cards", d.redeemInvite()),
		guest("request_contact", "Ask to become a contact; the owner approves", d.requestContact()),

		pending("contact_accepted", "Tell me my contact request was accepted", d.contactAccepted()),
		pending("contact_rejected", "Tell me my contact request was declined", d.contactRejected()),

		// always available at contact tier, regardless of the switchboard
		contact("get_card", "", "Fetch my current signed contact card", d.getCard()),
		contact("update_contact", "", "Replace my card after a key rotation", d.updateContact()),
		contact("remove_contact", "", "Remove yourself from my contacts", d.removeContact()),

		contact("send_message", "message.text", "Send a text message", d.sendMessage()),
		contact("send_media", "message.media", "Send a file or image", d.sendMedia()),
		contact("get_status", "status.view", "Read my availability status", d.getStatus()),
		contact("check_availability", "calendar.availability", "Ask for candidate meeting slots", d.checkAvailability()),
		contact("book_slot", "calendar.book", "Book one of the offered slots", d.bookSlot()),
		contact("cancel_booking", "calendar.book", "Cancel a booking you made", d.cancelBooking()),
	}
}

/* ------------------------------ guest tier ------------------------------ */

func (d ToolDeps) redeemInvite() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Token string `json:"token"`
			Card  string `json:"card"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Card, MaxTextBytes) || !capped(a.Token, MaxFieldBytes) {
			d.audit("redeem_invite", "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		// The key the caller PROVED this call: envelope `spk` when sealed, the
		// client certificate otherwise — or, in 2.0, the chain. Never the
		// card's self-claim.
		proof := d.proofOf(ctx)
		fpr := proof.Fingerprint
		res, err := d.Contacts.RedeemAs(ctx, d.AccountID, a.Token, a.Card, proof)
		if err != nil {
			d.audit("redeem_invite", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		// The caller's tier just changed: its cached guest server must go.
		d.invalidate(ctx, fpr)
		card, sig, mySPKI, cerr := d.card(ctx)
		if cerr != nil {
			return toolErr("unavailable"), nil
		}
		d.audit("redeem_invite", "caller:"+fpr, res.Status)
		return toolOK(map[string]any{
			"status": res.Status, "permissions": res.Permissions,
			"card": card, "card_sig": sig,
			"spki": base64.RawURLEncoding.EncodeToString(mySPKI),
		})
	}
}

func (d ToolDeps) requestContact() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Card string `json:"card"`
			Note string `json:"note"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Note, MaxNoteBytes) || !capped(a.Card, MaxTextBytes) {
			d.audit("request_contact", "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		proof := d.proofOf(ctx)
		fpr := proof.Fingerprint
		if err := d.Contacts.RequestContactAs(ctx, d.AccountID, a.Card, a.Note, proof); err != nil {
			switch known(ctx, d, fpr) {
			case "blocked":
				// SPEC §9.1: blocked MUST be indistinguishable from never-met.
				// The stranger's answer is returned verbatim and nothing is
				// recorded toward the owner; only the audit log knows.
				d.audit("request_contact", "caller:"+fpr, "blocked_silent")
				return toolOK(map[string]string{"status": "pending"})
			case "pending_in":
				// A repeat while the owner is still deciding is its own code and
				// creates no duplicate request (SPEC §9.1, PACT §12).
				d.audit("request_contact", "caller:"+fpr, "pending_approval")
				return toolErr("pending_approval"), nil
			}
			code := domainCode(err)
			d.audit("request_contact", "caller:"+fpr+" "+why(err), code)
			return toolErr(code), nil
		}
		d.audit("request_contact", "caller:"+fpr, "pending")
		return toolOK(map[string]string{"status": "pending"})
	}
}

// known returns the caller's stored relationship status, or "" when there is
// none — the difference between "your card is unparseable", "you already asked"
// and "you are blocked", each of which the spec answers differently.
func known(ctx context.Context, d ToolDeps, fpr string) string {
	if fpr == "" || d.Contacts == nil || d.Contacts.Store == nil {
		return ""
	}
	c, err := d.Contacts.Store.GetContact(ctx, d.AccountID, fpr)
	if err != nil {
		return ""
	}
	return c.Status
}

/* ----------------------------- pending tier ----------------------------- */

func (d ToolDeps) contactAccepted() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Card string `json:"card"`
			// what they granted US (PACT §6.2) — the list an agent needs so it
			// does not have to discover a contact's surface by probing
			Permissions []string `json:"permissions"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Card, MaxTextBytes) || len(a.Permissions) > 64 {
			return toolErr("too_large"), nil
		}
		for _, p := range a.Permissions {
			if !capped(p, MaxFieldBytes) {
				return toolErr("too_large"), nil
			}
		}
		fpr := callerFpr(ctx)
		if err := d.Contacts.ContactAccepted(ctx, d.AccountID, fpr, a.Card, a.Permissions); err != nil {
			d.audit("contact_accepted", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit("contact_accepted", "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

func (d ToolDeps) contactRejected() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Reason string `json:"reason"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Reason, MaxNoteBytes) {
			return toolErr("too_large"), nil
		}
		fpr := callerFpr(ctx)
		if err := d.Contacts.ContactRejected(ctx, d.AccountID, fpr); err != nil {
			d.audit("contact_rejected", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit("contact_rejected", "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

/* ---------------------- contact tier: always present -------------------- */

func (d ToolDeps) card(ctx context.Context) (string, string, []byte, error) {
	if d.Card == nil {
		return "", "", nil, fmt.Errorf("no card configured")
	}
	return d.Card(ctx)
}

func (d ToolDeps) getCard() mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		card, sig, spki, err := d.card(ctx)
		if err != nil {
			return toolErr("unavailable"), nil
		}
		limits := DefaultLimits()
		if d.Limits != nil {
			limits = d.Limits()
		}
		d.audit("get_card", "caller:"+callerFpr(ctx), "ok")
		return toolOK(map[string]any{
			"card": card, "card_sig": sig,
			"spki":   base64.RawURLEncoding.EncodeToString(spki),
			"limits": limits,
		})
	}
}

func (d ToolDeps) updateContact() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Card string `json:"card"`
			Sig  string `json:"sig"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Card, MaxTextBytes) || !capped(a.Sig, MaxFieldBytes) {
			return toolErr("too_large"), nil
		}
		sig, err := base64.RawURLEncoding.DecodeString(a.Sig)
		if err != nil {
			return toolErr("bad_request"), nil
		}
		fpr := callerFpr(ctx)
		// The peer is calling as its OLD identity; the new key it proves this
		// call (if any) is what the manager may pin.
		if err := d.Contacts.UpdateContact(ctx, d.AccountID, fpr, a.Card, sig, CallerSPKI(ctx)); err != nil {
			d.audit("update_contact", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit("update_contact", "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

func (d ToolDeps) removeContact() mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fpr := callerFpr(ctx)
		if err := d.Contacts.RemoveContact(ctx, d.AccountID, fpr); err != nil {
			d.audit("remove_contact", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit("remove_contact", "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

/* --------------------- contact tier: permission-gated -------------------- */

// senderLabel takes the peer's claim at face value (PACT §7: honest labeling is
// the sender's obligation) but only from the fixed vocabulary. Absent, it is
// `agent` — the safe direction: a node never invents a "human" claim.
func senderLabel(claimed string) (messaging.Sender, bool) {
	switch claimed {
	case "":
		return messaging.SenderAgent, true
	case string(messaging.SenderAgent):
		return messaging.SenderAgent, true
	case string(messaging.SenderHuman):
		return messaging.SenderHuman, true
	default:
		return "", false
	}
}

func (d ToolDeps) sendMessage() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Messages == nil {
			d.audit("send_message", "caller:"+callerFpr(ctx)+" why:no messaging service is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			MsgID    string `json:"msg_id"`
			ThreadID string `json:"thread_id"`
			Topic    string `json:"topic"`
			Text     string `json:"text"`
			ReplyTo  string `json:"reply_to"`
			Sender   string `json:"sender"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Text, MaxTextBytes) {
			d.audit("send_message", "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		if !capped(a.Topic, MaxFieldBytes) || !capped(a.MsgID, MaxFieldBytes) ||
			!capped(a.ThreadID, MaxFieldBytes) || !capped(a.ReplyTo, MaxFieldBytes) {
			return toolErr("too_large"), nil
		}
		sender, ok := senderLabel(a.Sender)
		if !ok {
			return toolErr("bad_request"), nil
		}
		fpr := callerFpr(ctx)
		res, err := d.Messages.Record(ctx, d.AccountID, fpr, messaging.DirIn, messaging.Input{
			MsgID: a.MsgID, ThreadID: a.ThreadID, Topic: a.Topic,
			Text: a.Text, ReplyTo: a.ReplyTo, Origin: messaging.OriginPeer, Sender: sender,
		})
		if err != nil {
			d.audit("send_message", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit("send_message", "caller:"+fpr, res.Status)
		return toolOK(map[string]string{"thread_id": res.ThreadID, "status": res.Status})
	}
}

func (d ToolDeps) sendMedia() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Media == nil || d.Messages == nil {
			d.audit("send_media", "caller:"+callerFpr(ctx)+" why:no media service is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			MsgID    string `json:"msg_id"`
			ThreadID string `json:"thread_id"`
			Filename string `json:"filename"`
			MIME     string `json:"mime"`
			Data     string `json:"data"`
			URL      string `json:"url"`
			Sender   string `json:"sender"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Filename, MaxFieldBytes) || !capped(a.MIME, MaxFieldBytes) ||
			!capped(a.URL, MaxFieldBytes) || !capped(a.MsgID, MaxFieldBytes) || !capped(a.ThreadID, MaxFieldBytes) {
			return toolErr("too_large"), nil
		}
		// Cap the ENCODED form first: refuse before allocating the decode.
		if len(a.Data) > base64.StdEncoding.EncodedLen(MaxInlineData) {
			d.audit("send_media", "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		sender, ok := senderLabel(a.Sender)
		if !ok {
			return toolErr("bad_request"), nil
		}
		fpr := callerFpr(ctx)
		in := messaging.Input{MsgID: a.MsgID, ThreadID: a.ThreadID, Origin: messaging.OriginPeer, Sender: sender}
		var (
			res messaging.Result
			err error
		)
		switch {
		case a.Data != "":
			raw, derr := base64.StdEncoding.DecodeString(a.Data)
			if derr != nil {
				return toolErr("bad_request"), nil
			}
			if len(raw) > MaxInlineData {
				d.audit("send_media", "caller:"+fpr, "too_large")
				return toolErr("too_large"), nil
			}
			res, err = d.Media.ReceiveInline(ctx, d.Messages, d.AccountID, fpr, in, a.Filename, a.MIME, raw)
		case a.URL != "":
			// Never fetched here (SPEC §7.5): the reference is recorded and the
			// owner decides.
			res, err = d.Media.ReceiveURL(ctx, d.Messages, d.AccountID, fpr, in, a.Filename, a.MIME, a.URL)
		default:
			return toolErr("bad_request"), nil
		}
		if err != nil {
			d.audit("send_media", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit("send_media", "caller:"+fpr, res.Status)
		return toolOK(map[string]string{"thread_id": res.ThreadID, "status": res.Status})
	}
}

func (d ToolDeps) getStatus() mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Status == nil {
			d.audit("get_status", "caller:"+callerFpr(ctx)+" why:no status is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		s, err := d.Status.GetStatus(ctx)
		if err != nil {
			d.audit("get_status", "caller:"+callerFpr(ctx)+" "+why(err), "unavailable")
			return toolErr("unavailable"), nil
		}
		d.audit("get_status", "caller:"+callerFpr(ctx), "ok")
		return toolOK(map[string]string{"status": clampStatus(s)})
	}
}

// clampStatus holds get_status to PACT §6.2's four-value vocabulary at the one
// wire boundary every StatusSource passes through. A recipe-sourced status is
// whatever string the upstream tool's mapped field contained — "in-a-meeting",
// say — and forwarding it verbatim broke the result contract for every
// conforming caller. Anything unknown maps to busy (the spec's rule): richer
// states are almost always flavors of "not free", and the raw value never
// crosses the wire.
func clampStatus(s string) string {
	switch s {
	case "available", "busy", "dnd", "offline":
		return s
	}
	return "busy"
}

func (d ToolDeps) checkAvailability() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Calendar == nil {
			d.audit("check_availability", "caller:"+callerFpr(ctx)+" why:no calendar is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			Window struct {
				From string `json:"from"`
				To   string `json:"to"`
				TZ   string `json:"tz"`
			} `json:"window"`
			DurationMin int `json:"duration_min"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		from, err1 := time.Parse(time.RFC3339, a.Window.From)
		to, err2 := time.Parse(time.RFC3339, a.Window.To)
		if err1 != nil || err2 != nil || !to.After(from) || a.DurationMin <= 0 {
			return toolErr("bad_request"), nil
		}
		fpr := callerFpr(ctx)
		slots, err := d.Calendar.CheckAvailability(ctx, from, to, time.Duration(a.DurationMin)*time.Minute)
		if err != nil {
			d.audit("check_availability", "caller:"+fpr+" "+why(err), "unavailable")
			return toolErr("unavailable"), nil
		}
		// PACT §12: never more than five, and never raw free/busy. The provider
		// caps too; this is the boundary's own belt.
		if len(slots) > providers.MaxSlots {
			slots = slots[:providers.MaxSlots]
		}
		out := wireSlots(slots, zoneOf(a.Window.TZ))
		d.audit("check_availability", fmt.Sprintf("caller:%s slots:%d", fpr, len(out)), "ok")
		return toolOK(map[string]any{"slots": out})
	}
}

func (d ToolDeps) bookSlot() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Calendar == nil {
			d.audit("book_slot", "caller:"+callerFpr(ctx)+" why:no calendar is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			MsgID    string `json:"msg_id"`
			Slot     Slot   `json:"slot"`
			Subject  string `json:"subject"`
			ThreadID string `json:"thread_id"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.Subject, MaxFieldBytes) || !capped(a.MsgID, MaxFieldBytes) || !capped(a.ThreadID, MaxFieldBytes) {
			return toolErr("too_large"), nil
		}
		if a.MsgID == "" {
			return toolErr("bad_request"), nil
		}
		start, err1 := time.Parse(time.RFC3339, a.Slot.Start)
		end, err2 := time.Parse(time.RFC3339, a.Slot.End)
		if err1 != nil || err2 != nil || !end.After(start) {
			return toolErr("bad_request"), nil
		}
		fpr := callerFpr(ctx)
		ack, err := d.Calendar.BookSlot(ctx, fpr, a.MsgID, providers.Slot{Start: start, End: end}, a.Subject)
		if err != nil {
			d.audit("book_slot", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit("book_slot", "caller:"+fpr+" booking:"+ack.BookingID, "ok")
		return toolOK(ack)
	}
}

func (d ToolDeps) cancelBooking() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Calendar == nil {
			d.audit("cancel_booking", "caller:"+callerFpr(ctx)+" why:no calendar is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			BookingID string `json:"booking_id"`
			Reason    string `json:"reason"`
		}
		if !decode(req, &a) {
			return toolErr("bad_request"), nil
		}
		if !capped(a.BookingID, MaxFieldBytes) || !capped(a.Reason, MaxNoteBytes) {
			return toolErr("too_large"), nil
		}
		if a.BookingID == "" {
			return toolErr("bad_request"), nil
		}
		fpr := callerFpr(ctx)
		if err := d.Calendar.CancelBooking(ctx, a.BookingID); err != nil {
			d.audit("cancel_booking", "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit("cancel_booking", "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

// why renders a capability failure for the audit. A refusal that records only
// "unavailable" cannot answer whether the owner has no calendar configured or
// their calendar refused the call — the two need opposite fixes, and the owner
// is the one who has to tell them apart.
func why(err error) string {
	if err == nil {
		return "why:unknown"
	}
	// Redact BEFORE truncating: a secret cut in half is still a secret's prefix,
	// and truncation would leave a partial token in the trail.
	m := core.Redact(err.Error())
	if len(m) > 160 {
		m = m[:160] + "…"
	}
	return "why:" + m
}

// DefaultLimits is the untuned node's advertisement: every number from the
// same constant that enforces it, so the card can never disagree with the gate.
func DefaultLimits() Limits {
	return Limits{
		TextBytes:           MaxTextBytes,
		NoteBytes:           MaxNoteBytes,
		MediaInlineBytes:    MaxInlineData,
		AvailabilitySlots:   providers.MaxSlots,
		InviteTTLDays:       int(contacts.MaxInviteTTL / (24 * time.Hour)),
		ContactCallsPerHour: DefaultBudget(KindContact),
		GuestCallsPerHour:   DefaultBudget(KindGuest),
	}
}

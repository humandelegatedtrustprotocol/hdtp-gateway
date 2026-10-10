package public

// The built-in tool set of HDTP §6.2 (SPEC §5.6: "built-in tools ... execute
// against the node's own store"). This file is the ONLY place those tools are
// defined; the registry, the pool and `policy.Allow` decide who sees which.
//
// Three rules hold for every handler here:
//
//   - Caller identity is the RESOLVED one — `CallerFromContext` for a pinned
//     contact, `proofOf` for what a guest proved this call (the chain an
//     envelope or a client certificate carried). No handler reads an identity
//     out of its arguments.
//   - Untrusted strings are capped at the boundary and REFUSED when over, never
//     silently truncated, and never concatenated into an instruction.
//   - Every call answers with an HDTP §12 code on failure, and audits.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/calendar"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Boundary caps (HDTP §12, SPEC §5.7). The store enforces them again.
const (
	// MaxTextBytes caps a message's text, and a card argument.
	MaxTextBytes = 16 * 1024
	// MaxNoteBytes caps a request note and a cancel or reject reason.
	MaxNoteBytes = 1024
	// MaxInlineData caps decoded inline media.
	MaxInlineData = 5 * 1024 * 1024
	// MaxFieldBytes caps a short field.
	MaxFieldBytes = 1024 // filename, mime, subject, topic, booking_id, msg_id, thread_id, token, url
)

// Calendar is the calendar capability as the public surface needs it — the
// three HDTP tools, nothing else. `*providers.Calendar` satisfies it.
type Calendar interface {
	// CheckAvailability returns candidate slots for a meeting of length d between from and to. The
	// tool caps them at calendar.MaxSlots before answering.
	CheckAvailability(ctx context.Context, from, to time.Time, d time.Duration) ([]calendar.Slot, error)
	// BookSlot books slot for the contact; msgID is the call's idempotency key.
	BookSlot(ctx context.Context, contactFpr, msgID string, slot calendar.Slot, subject string) (calendar.BookingAck, error)
	// CancelBooking cancels a booking by id.
	CancelBooking(ctx context.Context, bookingID string) error
}

// Slot is the wire shape HDTP §6.2 gives a candidate interval: RFC 3339
// instants plus the IANA zone they are rendered in. The provider works in
// time.Time; this boundary is where the zone is chosen and stated.
type Slot struct {
	// Start is the interval's start, RFC 3339 in the zone TZ names.
	Start string `json:"start"`
	// End is the interval's end, RFC 3339 in the zone TZ names.
	End string `json:"end"`
	// TZ is the IANA zone the instants are rendered in; UTC when the caller asked for none or an unknown one.
	TZ string `json:"tz"`
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

func wireSlots(in []calendar.Slot, loc *time.Location) []Slot {
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
	// GetStatus returns the owner's availability; the tool clamps it to available, busy, dnd or offline.
	GetStatus(ctx context.Context) (string, error)
}

// CardFn returns this account's current SIGNED card and the signature over it. HDTP §4 says
// redemption returns the issuer's signed card, and the same card has to read the same over every
// transport — signed on the landing page and signed over MCP. It used to return the leaf's key as
// well, for a `spki` member beside the card: 1.2's answer to a card that carried only a key's
// hash. A card carries the certificate, and the chain travels beside it instead.
type CardFn func(ctx context.Context) (card, sig string, err error)

// ToolDeps is everything the built-in set touches. A nil capability is not an
// error: its tools answer `unavailable` (HDTP §12's code for a capability the
// implementation is currently withholding).
type ToolDeps struct {
	// AccountID scopes every store call and audit row the tools make.
	AccountID string
	// Contacts is the contact manager; the guest, pending and contact-management tools need it.
	Contacts *contacts.Manager
	// Messages records inbound messages; send_message and send_media answer `unavailable` without it.
	Messages *messaging.Service
	// Media receives inline and URL media; send_media answers `unavailable` without it.
	Media *messaging.MediaService
	// Calendar backs check_availability, book_slot and cancel_booking.
	Calendar Calendar
	// Status backs get_status; with none the tool answers `unavailable` (internal/node supplies one that defaults to available).
	Status StatusSource
	// Card returns the signed card for redeem_invite and get_card.
	Card CardFn
	// Invalidate drops a caller's cached MCP server after its tier changes.
	Invalidate func(ctx context.Context, accountID, fpr string) error
	// Audit receives each tool's audit row when AuditAs is not set.
	Audit AuditFn
	// AuditAs, when set, is used instead of Audit and is told who acted (see audit).
	AuditAs func(kind, action, resource, outcome string)
	// Limits reports the limits in force, for get_card's metadata (HDTP §12): the sizes, and the call
	// budgets the limits sidecar enforces for this account. Asked per call, because the contact cap
	// that sizes the aggregate is an owner knob and the sidecar may be restarted with other numbers.
	// An error, or no function at all, answers get_card `unavailable`: there is no compiled-in copy of
	// the budgets to advertise instead.
	Limits func(ctx context.Context) (Limits, error)
	// Endpoint is this account's own address, for the guard a guest's card
	// must pass (HDTP §3: never the receiver's own). nil means unknown.
	Endpoint func() string
	// Chain is this account's [leaf, root]. `redeem_invite` and `get_card` both answer with
	// it (HDTP §6.2, §13.2), so a caller that cannot verify a result has one place to ask.
	Chain func(ctx context.Context) ([][]byte, error)
}

// holdsLeaf reports whether this account holds a leaf, and so has a chain to answer with.
func (d ToolDeps) holdsLeaf(ctx context.Context) bool {
	if d.Chain == nil {
		return false
	}
	chain, err := d.Chain(ctx)
	return err == nil && len(chain) == 2
}

// proofOf is what the caller proved this call, for the guest tools to pin: the
// root, the leaf's key, the endpoint and the leaf the chain carried (HDTP §14.2
// rule 6). A caller that proved no chain proves no identity — a bare key is
// not one — and the zero Proof is refused upstream.
func (d ToolDeps) proofOf(ctx context.Context) contacts.Proof {
	if f := EnvelopeFactsFrom(ctx); f != nil && f.Refusal == "" {
		p := contacts.Proof{Fingerprint: f.From, SPKI: f.SPKI, Endpoint: f.Endpoint, Leaf: f.Leaf, AddressClaim: f.AddressClaim}
		if d.Endpoint != nil {
			p.SelfEndpoint = d.Endpoint()
		}
		return p
	}
	tf := FactsFrom(ctx)
	if tf.ChainProven() && d.holdsLeaf(ctx) {
		p := contacts.Proof{Fingerprint: tf.ClientCertFingerprint, SPKI: tf.ClientCertSPKI, Endpoint: tf.ClientEndpoint, Leaf: tf.ClientLeaf, RootCert: tf.ClientRoot}
		if d.Endpoint != nil {
			p.SelfEndpoint = d.Endpoint()
		}
		// A sealed guest's claim comes from the core's Decide (above); one proven by its client
		// certificate never reaches Decide, so the same rule is asked of the store here. A claim
		// that cannot be read is treated as one: the owner decides.
		claim, err := d.Contacts.AddressClaim(ctx, d.AccountID, p.Endpoint, p.Fingerprint)
		if err != nil {
			claim = "unreadable"
		}
		p.AddressClaim = claim
		return p
	}
	return contacts.Proof{}
}

// audit records one boundary event. The outcome is a verdict and nothing else:
// it is what the portal colours, counts and filters by, so a caller fingerprint
// or a failure sentence in that column turns every row into its own category.
// Those belong in the resource, which is the free-text locator (SPEC §11.5).
//
// With AuditAs set the row names who acted, in the store's actor vocabulary: the two guest tools
// are a guest's, every other tool here is reached only at the pending or contact tier (the
// switchboard serves nothing else), which the store calls `contact` — Pool.audit's mapping.
func (d ToolDeps) audit(action, resource, outcome string) {
	if d.AuditAs != nil {
		kind := "contact"
		if action == core.ToolRedeemInvite || action == core.ToolRequestContact {
			kind = "guest"
		}
		d.AuditAs(kind, action, resource, outcome)
		return
	}
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// refuse audits a refusal a handler decides before it knows anything else — an argument that does
// not decode, a field past its cap, a value outside its vocabulary — and returns it. Every refusal
// is on the trail (build rule 7): these used to answer the caller and write nothing, so a peer
// probing a node with malformed calls left no trace.
func (d ToolDeps) refuse(ctx context.Context, action, code string) *mcp.CallToolResult {
	d.audit(action, "caller:"+callerFpr(ctx), code)
	return toolErr(code)
}

func (d ToolDeps) invalidate(ctx context.Context, fpr string) {
	if d.Invalidate != nil && fpr != "" {
		_ = d.Invalidate(ctx, d.AccountID, fpr)
	}
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

// domainCode maps a domain error to its HDTP §12 code. The sentinels carry the
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

// tool is one built-in tool's definition: its name, its description, an open object schema and
// its four hints (hints.go).
func tool(name, desc string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: desc, InputSchema: objSchema(), Annotations: hintsOf(name)}
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

// BuiltinEntries returns the HDTP §6.2 core tools for one account, each tagged
// with the tier and permission that gate it (SPEC §5.4). The README of this
// package lists each tool's gate and refusals. The set is held equal to core.ReservedToolNames
// (with sealed_call) by TestTheReservedToolNamesAreTheBuiltInSet.
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
		guest(core.ToolRedeemInvite, "Redeem an invite token and exchange cards", d.redeemInvite()),
		guest(core.ToolRequestContact, "Ask to become a contact; the owner approves", d.requestContact()),

		pending(core.ToolContactAccepted, "Tell me my contact request was accepted", d.contactAccepted()),
		pending(core.ToolContactRejected, "Tell me my contact request was declined", d.contactRejected()),

		// always available at contact tier, regardless of the switchboard
		contact(core.ToolGetCard, "", "Fetch my current signed contact card", d.getCard()),
		contact(core.ToolUpdateContact, "", "Replace the card you hold for me: I have a new certificate, or a new address", d.updateContact()),
		contact(core.ToolRemoveContact, "", "Remove yourself from my contacts", d.removeContact()),

		contact(core.ToolSendMessage, "message.text", "Send a text message", d.sendMessage()),
		contact(core.ToolSendMedia, "message.media", "Send a file or image", d.sendMedia()),
		contact(core.ToolGetStatus, "status.view", "Read my availability status", d.getStatus()),
		contact(core.ToolCheckAvailability, "calendar.availability", "Ask for candidate meeting slots", d.checkAvailability()),
		contact(core.ToolBookSlot, "calendar.book", "Book one of the offered slots", d.bookSlot()),
		contact(core.ToolCancelBooking, "calendar.book", "Cancel a booking you made", d.cancelBooking()),
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
			return d.refuse(ctx, core.ToolRedeemInvite, "bad_request"), nil
		}
		if !capped(a.Card, MaxTextBytes) || !capped(a.Token, MaxFieldBytes) {
			d.audit(core.ToolRedeemInvite, "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		// The key the caller PROVED this call: the leaf of the chain the
		// envelope or the client certificate carried. Never the card's
		// self-claim.
		proof := d.proofOf(ctx)
		fpr := proof.Fingerprint
		res, err := d.Contacts.RedeemAs(ctx, d.AccountID, a.Token, a.Card, proof)
		if err != nil {
			d.audit(core.ToolRedeemInvite, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		// The caller's tier just changed: its cached guest server must go. A silent answer
		// changed nothing, so there is nothing to drop.
		if !res.Silent {
			d.invalidate(ctx, fpr)
		}
		card, sig, cerr := d.card(ctx)
		if cerr != nil {
			return d.refuse(ctx, core.ToolRedeemInvite, "unavailable"), nil
		}
		// HDTP §6.2: the result carries the issuer's CHAIN, so the redeemer pins a root it can
		// verify. It used to carry `spki` instead — 1.2's key-beside-the-card — and no chain.
		chain, cerr := d.chainB64(ctx)
		if cerr != nil {
			return d.refuse(ctx, core.ToolRedeemInvite, "unavailable"), nil
		}
		outcome := res.Status
		if res.Silent {
			// SPEC §9.1: answered as a stranger; only the audit log knows.
			outcome = silentOutcome(known(ctx, d, fpr))
		}
		resource := "caller:" + fpr
		if proof.AddressClaim != "" {
			// HDTP §5.2: the owner sees whose address this is; the audit row is where it is kept.
			resource += " address_of:" + proof.AddressClaim
		}
		d.audit(core.ToolRedeemInvite, resource, outcome)
		return toolOK(map[string]any{
			"status": res.Status, "permissions": res.Permissions,
			"card": card, "card_sig": sig, "chain": chain,
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
			return d.refuse(ctx, core.ToolRequestContact, "bad_request"), nil
		}
		if !capped(a.Note, MaxNoteBytes) || !capped(a.Card, MaxTextBytes) {
			d.audit(core.ToolRequestContact, "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		proof := d.proofOf(ctx)
		fpr := proof.Fingerprint
		if err := d.Contacts.RequestContactAs(ctx, d.AccountID, a.Card, a.Note, proof); err != nil {
			status := known(ctx, d, fpr)
			if status != "pending_in" && errors.Is(err, contacts.ErrRequestsFull) {
				// A full list of requests, or a cap the sidecar could not be asked about: `unavailable`
				// to everybody who would have been written, a blocked caller included (SPEC §9.1).
				d.audit(core.ToolRequestContact, "caller:"+fpr+" "+why(err), "unavailable")
				return toolErr("unavailable"), nil
			}
			switch status {
			case "":
			case "pending_in":
				// A repeat while the owner is still deciding is its own code and
				// creates no duplicate request (SPEC §9.1, HDTP §12).
				d.audit(core.ToolRequestContact, "caller:"+fpr, "pending_approval")
				return toolErr("pending_approval"), nil
			default:
				// Any other row this account holds: blocked, or an active or pending_out contact the
				// node served at the guest tier because the leaf that signed is older than the one it
				// holds (HDTP §14.3). HDTP §5: such a caller hears exactly what a stranger hears, and
				// nothing is recorded toward the owner; only the audit log knows. The same rule
				// RedeemAs applies to a held row, and the cloud's request_contact
				// (batondeck src/identity/tools.ts). An active row here was answered `bad_request`
				// "already known", which told a demoted caller it is known.
				d.audit(core.ToolRequestContact, "caller:"+fpr, silentOutcome(status))
				return toolOK(map[string]string{"status": "pending"})
			}
			code := domainCode(err)
			d.audit(core.ToolRequestContact, "caller:"+fpr+" "+why(err), code)
			return toolErr(code), nil
		}
		d.audit(core.ToolRequestContact, "caller:"+fpr, "pending")
		return toolOK(map[string]string{"status": "pending"})
	}
}

// silentOutcome is the audit verdict for a guest tool that answered a held root as it answers a
// stranger and wrote nothing (HDTP §5). A blocked row is `blocked_silent`. An active or pending_out
// row reaches a guest tool only demoted, and nobody blocked it: `ok`, the call answered and nothing
// refused, which is the row the cloud writes for the same answer (batondeck
// src/identity/surface.ts, the pipeline's write after a tool that does not throw).
func silentOutcome(status string) string {
	if status == "blocked" {
		return "blocked_silent"
	}
	return "ok"
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
			// what they granted US (HDTP §6.2) — the list an agent needs so it
			// does not have to discover a contact's surface by probing
			Permissions []string `json:"permissions"`
		}
		if !decode(req, &a) {
			return d.refuse(ctx, core.ToolContactAccepted, "bad_request"), nil
		}
		if !capped(a.Card, MaxTextBytes) || len(a.Permissions) > 64 {
			return d.refuse(ctx, core.ToolContactAccepted, "too_large"), nil
		}
		for _, p := range a.Permissions {
			if !capped(p, MaxFieldBytes) {
				return d.refuse(ctx, core.ToolContactAccepted, "too_large"), nil
			}
		}
		fpr := callerFpr(ctx)
		if err := d.Contacts.ContactAccepted(ctx, d.AccountID, fpr, a.Card, a.Permissions); err != nil {
			d.audit(core.ToolContactAccepted, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit(core.ToolContactAccepted, "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

func (d ToolDeps) contactRejected() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Reason string `json:"reason"`
		}
		if !decode(req, &a) {
			return d.refuse(ctx, core.ToolContactRejected, "bad_request"), nil
		}
		if !capped(a.Reason, MaxNoteBytes) {
			return d.refuse(ctx, core.ToolContactRejected, "too_large"), nil
		}
		fpr := callerFpr(ctx)
		if err := d.Contacts.ContactRejected(ctx, d.AccountID, fpr); err != nil {
			d.audit(core.ToolContactRejected, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit(core.ToolContactRejected, "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

/* ---------------------- contact tier: always present -------------------- */

func (d ToolDeps) card(ctx context.Context) (string, string, error) {
	if d.Card == nil {
		return "", "", fmt.Errorf("no card configured")
	}
	return d.Card(ctx)
}

// chainB64 is this account's [leaf, root], base64url — what `redeem_invite` and `get_card` both
// answer with (HDTP §6.2, §13.2). It is never optional: a result that cannot carry the chain is
// one the caller cannot verify, and the honest answer then is `unavailable`.
func (d ToolDeps) chainB64(ctx context.Context) ([]string, error) {
	if d.Chain == nil {
		return nil, fmt.Errorf("no chain configured")
	}
	chain, err := d.Chain(ctx)
	if err != nil {
		return nil, err
	}
	if len(chain) != 2 {
		return nil, fmt.Errorf("a chain is a leaf and a root, got %d certificates", len(chain))
	}
	return []string{hdtpidentity.B64url(chain[0]), hdtpidentity.B64url(chain[1])}, nil
}

func (d ToolDeps) getCard() mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		card, sig, err := d.card(ctx)
		if err != nil {
			return d.refuse(ctx, core.ToolGetCard, "unavailable"), nil
		}
		// "always the chain" (HDTP §6.2): this is where a caller that cannot verify a result
		// comes to ask, so an answer without one would be no answer.
		chain, err := d.chainB64(ctx)
		if err != nil {
			return d.refuse(ctx, core.ToolGetCard, "unavailable"), nil
		}
		if d.Limits == nil {
			return d.refuse(ctx, core.ToolGetCard, "unavailable"), nil
		}
		limits, err := d.Limits(ctx)
		if err != nil {
			return d.refuse(ctx, core.ToolGetCard, "unavailable"), nil
		}
		d.audit(core.ToolGetCard, "caller:"+callerFpr(ctx), "ok")
		out := map[string]any{
			"card": card, "card_sig": sig, "chain": chain,
			"limits": limits,
		}
		return toolOK(out)
	}
}

func (d ToolDeps) updateContact() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Card string `json:"card"`
		}
		if !decode(req, &a) {
			return d.refuse(ctx, core.ToolUpdateContact, "bad_request"), nil
		}
		if !capped(a.Card, MaxTextBytes) {
			return d.refuse(ctx, core.ToolUpdateContact, "too_large"), nil
		}
		fpr := callerFpr(ctx)
		// The chain that carried this call already decided the pin (HDTP §5.3,
		// §14.3); what this refreshes is the card beside it.
		if err := d.Contacts.UpdateContact(ctx, d.AccountID, fpr, a.Card); err != nil {
			d.audit(core.ToolUpdateContact, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit(core.ToolUpdateContact, "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

func (d ToolDeps) removeContact() mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fpr := callerFpr(ctx)
		if err := d.Contacts.RemoveContact(ctx, d.AccountID, fpr); err != nil {
			d.audit(core.ToolRemoveContact, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.invalidate(ctx, fpr)
		d.audit(core.ToolRemoveContact, "caller:"+fpr, "ok")
		return toolOK(map[string]string{"status": "ok"})
	}
}

/* --------------------- contact tier: permission-gated -------------------- */

// senderLabel takes the peer's claim at face value (HDTP §7: honest labeling is
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
			d.audit(core.ToolSendMessage, "caller:"+callerFpr(ctx)+" why:no messaging service is configured", "unavailable")
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
			return d.refuse(ctx, core.ToolSendMessage, "bad_request"), nil
		}
		if !capped(a.Text, MaxTextBytes) {
			d.audit(core.ToolSendMessage, "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		if !capped(a.Topic, MaxFieldBytes) || !capped(a.MsgID, MaxFieldBytes) ||
			!capped(a.ThreadID, MaxFieldBytes) || !capped(a.ReplyTo, MaxFieldBytes) {
			return d.refuse(ctx, core.ToolSendMessage, "too_large"), nil
		}
		sender, ok := senderLabel(a.Sender)
		if !ok {
			return d.refuse(ctx, core.ToolSendMessage, "bad_request"), nil
		}
		fpr := callerFpr(ctx)
		res, err := d.Messages.Record(ctx, d.AccountID, fpr, messaging.DirIn, messaging.Input{
			MsgID: a.MsgID, ThreadID: a.ThreadID, Topic: a.Topic,
			Text: a.Text, ReplyTo: a.ReplyTo, Origin: messaging.OriginPeer, Sender: sender,
		})
		if err != nil {
			d.audit(core.ToolSendMessage, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit(core.ToolSendMessage, "caller:"+fpr, res.Status)
		return toolOK(map[string]string{"thread_id": res.ThreadID, "status": res.Status})
	}
}

func (d ToolDeps) sendMedia() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Media == nil || d.Messages == nil {
			d.audit(core.ToolSendMedia, "caller:"+callerFpr(ctx)+" why:no media service is configured", "unavailable")
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
			return d.refuse(ctx, core.ToolSendMedia, "bad_request"), nil
		}
		if !capped(a.Filename, MaxFieldBytes) || !capped(a.MIME, MaxFieldBytes) ||
			!capped(a.URL, MaxFieldBytes) || !capped(a.MsgID, MaxFieldBytes) || !capped(a.ThreadID, MaxFieldBytes) {
			return d.refuse(ctx, core.ToolSendMedia, "too_large"), nil
		}
		// Cap the ENCODED form first: refuse before allocating the decode.
		if len(a.Data) > base64.StdEncoding.EncodedLen(MaxInlineData) {
			d.audit(core.ToolSendMedia, "caller:"+callerFpr(ctx), "too_large")
			return toolErr("too_large"), nil
		}
		sender, ok := senderLabel(a.Sender)
		if !ok {
			return d.refuse(ctx, core.ToolSendMedia, "bad_request"), nil
		}
		// HDTP §6.2: msg_id is required. Refused here, before a byte is decoded or stored.
		if a.MsgID == "" {
			return d.refuse(ctx, core.ToolSendMedia, "bad_request"), nil
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
				return d.refuse(ctx, core.ToolSendMedia, "bad_request"), nil
			}
			if len(raw) > MaxInlineData {
				d.audit(core.ToolSendMedia, "caller:"+fpr, "too_large")
				return toolErr("too_large"), nil
			}
			res, err = d.Media.ReceiveInline(ctx, d.Messages, d.AccountID, fpr, in, a.Filename, a.MIME, raw)
		case a.URL != "":
			// Never fetched here (SPEC §7.5): the reference is recorded and the
			// owner decides.
			res, err = d.Media.ReceiveURL(ctx, d.Messages, d.AccountID, fpr, in, a.Filename, a.MIME, a.URL)
		default:
			return d.refuse(ctx, core.ToolSendMedia, "bad_request"), nil
		}
		if err != nil {
			d.audit(core.ToolSendMedia, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit(core.ToolSendMedia, "caller:"+fpr, res.Status)
		return toolOK(map[string]string{"thread_id": res.ThreadID, "status": res.Status})
	}
}

func (d ToolDeps) getStatus() mcp.ToolHandler {
	return func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Status == nil {
			d.audit(core.ToolGetStatus, "caller:"+callerFpr(ctx)+" why:no status is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		s, err := d.Status.GetStatus(ctx)
		if err != nil {
			d.audit(core.ToolGetStatus, "caller:"+callerFpr(ctx)+" "+why(err), "unavailable")
			return toolErr("unavailable"), nil
		}
		d.audit(core.ToolGetStatus, "caller:"+callerFpr(ctx), "ok")
		return toolOK(map[string]string{"status": clampStatus(s)})
	}
}

// clampStatus holds get_status to HDTP §6.2's four-value vocabulary at the one
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
			d.audit(core.ToolCheckAvailability, "caller:"+callerFpr(ctx)+" why:no calendar is configured", "unavailable")
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
			return d.refuse(ctx, core.ToolCheckAvailability, "bad_request"), nil
		}
		from, err1 := time.Parse(time.RFC3339, a.Window.From)
		to, err2 := time.Parse(time.RFC3339, a.Window.To)
		if err1 != nil || err2 != nil || !to.After(from) || a.DurationMin <= 0 {
			return d.refuse(ctx, core.ToolCheckAvailability, "bad_request"), nil
		}
		fpr := callerFpr(ctx)
		slots, err := d.Calendar.CheckAvailability(ctx, from, to, time.Duration(a.DurationMin)*time.Minute)
		if err != nil {
			d.audit(core.ToolCheckAvailability, "caller:"+fpr+" "+why(err), "unavailable")
			return toolErr("unavailable"), nil
		}
		// HDTP §12: never more than five, and never raw free/busy. The provider
		// caps too; this is the boundary's own belt.
		if len(slots) > calendar.MaxSlots {
			slots = slots[:calendar.MaxSlots]
		}
		out := wireSlots(slots, zoneOf(a.Window.TZ))
		d.audit(core.ToolCheckAvailability, fmt.Sprintf("caller:%s slots:%d", fpr, len(out)), "ok")
		return toolOK(map[string]any{"slots": out})
	}
}

func (d ToolDeps) bookSlot() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Calendar == nil {
			d.audit(core.ToolBookSlot, "caller:"+callerFpr(ctx)+" why:no calendar is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			MsgID    string `json:"msg_id"`
			Slot     Slot   `json:"slot"`
			Subject  string `json:"subject"`
			ThreadID string `json:"thread_id"`
		}
		if !decode(req, &a) {
			return d.refuse(ctx, core.ToolBookSlot, "bad_request"), nil
		}
		if !capped(a.Subject, MaxFieldBytes) || !capped(a.MsgID, MaxFieldBytes) || !capped(a.ThreadID, MaxFieldBytes) {
			return d.refuse(ctx, core.ToolBookSlot, "too_large"), nil
		}
		if a.MsgID == "" {
			return d.refuse(ctx, core.ToolBookSlot, "bad_request"), nil
		}
		start, err1 := time.Parse(time.RFC3339, a.Slot.Start)
		end, err2 := time.Parse(time.RFC3339, a.Slot.End)
		if err1 != nil || err2 != nil || !end.After(start) {
			return d.refuse(ctx, core.ToolBookSlot, "bad_request"), nil
		}
		fpr := callerFpr(ctx)
		ack, err := d.Calendar.BookSlot(ctx, fpr, a.MsgID, calendar.Slot{Start: start, End: end}, a.Subject)
		if err != nil {
			d.audit(core.ToolBookSlot, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit(core.ToolBookSlot, "caller:"+fpr+" booking:"+ack.BookingID, "ok")
		return toolOK(ack)
	}
}

func (d ToolDeps) cancelBooking() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Calendar == nil {
			d.audit(core.ToolCancelBooking, "caller:"+callerFpr(ctx)+" why:no calendar is configured", "unavailable")
			return toolErr("unavailable"), nil
		}
		var a struct {
			BookingID string `json:"booking_id"`
			Reason    string `json:"reason"`
		}
		if !decode(req, &a) {
			return d.refuse(ctx, core.ToolCancelBooking, "bad_request"), nil
		}
		if !capped(a.BookingID, MaxFieldBytes) || !capped(a.Reason, MaxNoteBytes) {
			return d.refuse(ctx, core.ToolCancelBooking, "too_large"), nil
		}
		if a.BookingID == "" {
			return d.refuse(ctx, core.ToolCancelBooking, "bad_request"), nil
		}
		fpr := callerFpr(ctx)
		if err := d.Calendar.CancelBooking(ctx, a.BookingID); err != nil {
			d.audit(core.ToolCancelBooking, "caller:"+fpr+" "+why(err), domainCode(err))
			return toolErr(domainCode(err)), nil
		}
		d.audit(core.ToolCancelBooking, "caller:"+fpr, "ok")
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

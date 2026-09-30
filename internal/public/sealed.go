package public

// `sealed_call` (SPEC §4.5, PACT §13.2): the one wrapper tool that carries
// sealing MCP-natively. It is present at EVERY tier — guest, pending, contact —
// so it is registered once per tier and exactly one entry matches any caller.
//
// The inner request is dispatched against the caller's own composed surface
// through the SAME policy path a direct call takes (Pool.Dispatch → guarded →
// policy.Allow), using the identity the envelope proved — which in edge mode is
// the only identity there is. The result is sealed back
// to that caller: a sealed request gets a sealed result, always.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/policy"
	"github.com/pact-cloud/pact-gateway/internal/envelope"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// SealedToolName is the wrapper's tool name on every tier.
const SealedToolName = "sealed_call"

// ResultLifetime bounds a result envelope's exp (well inside PACT's 30-day cap).
const ResultLifetime = 5 * time.Minute

// SealedDeps is what the wrapper needs for one account.
type SealedDeps struct {
	Pool       *Pool
	Identifier *Identifier
	AccountID  string
	// Idem is optional; nil disables envelope-level msg_id replay.
	Idem  IdempotencyStore
	Now   func() time.Time
	Audit func(action, resource, outcome string)
	// AuditAs, when set, is used instead of Audit and is told who acted in the store's actor
	// vocabulary: `guest` for an envelope that did not open or opened at the guest tier,
	// `contact` for a pending or active contact's. Every row used to be written as the node's
	// own (`system`), so the trail could not say that a stranger had knocked (the conformance
	// battery's "a guest is recorded as a guest", run against a node by harness S19).
	AuditAs func(kind, action, resource, outcome string)
}

func (d SealedDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d SealedDeps) audit(kind, action, resource, outcome string) {
	if d.AuditAs != nil {
		d.AuditAs(kind, action, resource, outcome)
		return
	}
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// actorOf is who a sealed call's facts say acted: a contact at the pending or contact tier, a
// guest otherwise — the mapping Pool.audit makes for a plaintext call.
func actorOf(f *EnvelopeFacts) string {
	if f != nil && (f.Tier == policy.TierContact || f.Tier == policy.TierPending) {
		return "contact"
	}
	return "guest"
}

// sealedTool is the tool definition; arguments are the four envelope members.
func sealedTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        SealedToolName,
		Description: "Carry a sealed PACT envelope; the inner call is dispatched as the envelope's proven identity and the result is sealed back",
		InputSchema: json.RawMessage(`{"type":"object","required":["protected","enc","ct","sig"],"properties":{"protected":{"type":"string"},"enc":{"type":"string"},"ct":{"type":"string"},"sig":{"type":"string"}},"additionalProperties":false}`),
	}
}

// SealedEntries returns the registry entries for `sealed_call` — one per tier,
// ungated by any permission, so every caller sees exactly one (SPEC §4.5).
func SealedEntries(d SealedDeps) []Entry {
	h := sealedHandler(d)
	out := make([]Entry, 0, 3)
	for _, tier := range []policy.Tier{policy.TierGuest, policy.TierPending, policy.TierContact} {
		out = append(out, Entry{Tool: sealedTool(), Rule: policy.Rule{Tier: tier}, Handler: h})
	}
	return out
}

// errEnvelope is the wire failure of the WRAPPER itself: a call that never got
// far enough to have a sealed answer (bad envelope, refused policy). The code
// travels as a plain tool error — there is no key to seal it to yet.
func errEnvelope(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + code + `"}`}}}
}

// spendGuestBudget charges one unit of the guest allowance and returns a
// rate_limited answer when it is gone. The wrapper is exempt from the per-call
// budget (see guarded), so an answer that costs the node work and tells the
// caller something must charge it here — a guessed fingerprint (§14.5), and
// equally a caller hammering an address the owner has not approved, which
// writes a row and wakes the owner for every attempt.
//
// `as` is which guest budget: ChargeSource for a small form answered chain_required, which proves
// no root, so its source address alone pays (PACT §12); ChargeGuest for a root the envelope did
// prove but that is not served as a contact here — at an address the owner has not approved, or
// at the pending tier — which pays the guest budget of that root at that address, whatever it is
// pinned as.
func spendGuestBudget(ctx context.Context, d SealedDeps, as Charge) *mcp.CallToolResult {
	if d.Pool == nil || d.Pool.Limit == nil {
		return nil
	}
	r := d.Pool.Limit(ctx, as)
	if r == nil {
		return nil
	}
	d.audit("guest", "sealed_call", "account:"+d.AccountID, r.Code())
	return r.Result()
}

func sealedHandler(d SealedDeps) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// The guest total, BEFORE the open (the owner's decision of 2026-09-29): from a source no
		// proven contact has used in the last hour, and with the account's total spent, the call is
		// refused here, in the clear, with nothing read and nothing opened.
		if r := d.Pool.preOpen(ctx); r != nil {
			d.audit("guest", "sealed_call", "account:"+d.AccountID, r.Code())
			return r.Result(), nil
		}
		var env pactidentity.Envelope
		if err := json.Unmarshal(req.Params.Arguments, &env); err != nil {
			// Not an envelope at all. Refused like any other that does not open, and audited like
			// one: this answered and wrote nothing.
			d.audit("guest", "sealed_call", "account:"+d.AccountID, "envelope_invalid")
			return errEnvelope("envelope_invalid"), nil
		}
		facts, err := d.Identifier.OpenSealed(ctx, d.AccountID, FactsFrom(ctx), &env)
		if err != nil {
			// Opened, and answered with a refusal that proves nobody: one call of the guest total,
			// whatever the total answers — the open is done, and the refusal below is the answer, and
			// the one row this call writes to the audit trail beside the budget's own.
			if errors.Is(err, errOpened) && d.Pool != nil && d.Pool.Limit != nil {
				_ = d.Pool.Limit(ctx, ChargeOpened)
			}
			var renewed *CertificateRenewed
			switch {
			case errors.Is(err, ErrChainRequired):
				// PACT §14.5: a guessed fingerprint spends the source's guest
				// budget. The wrapper is exempt from the per-call budget (see
				// guarded), so this answer charges it here, as a guest.
				if limited := spendGuestBudget(ctx, d, ChargeSource); limited != nil {
					return limited, nil
				}
			case errors.As(err, &renewed):
				// PACT §14.4: plaintext, carrying the current chain — proof of
				// nothing by itself; the caller validates it to its own pin.
				d.audit("guest", "sealed_call", "account:"+d.AccountID, "certificate_renewed")
				chain := make([]string, 0, len(renewed.Chain))
				for _, c := range renewed.Chain {
					chain = append(chain, pactidentity.B64url(c))
				}
				body, _ := json.Marshal(map[string]any{"code": "certificate_renewed", "data": map[string]any{"chain": chain}})
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
			}
			d.audit("guest", "sealed_call", "account:"+d.AccountID, Code(err))
			return errEnvelope(Code(err)), nil
		}
		if facts.Refusal != "" {
			// A pinned root at an address the owner has not approved (PACT
			// §5.3): the seed's plain code, nothing dispatched — and charged, so
			// a host calling from an unapproved address cannot do it for free.
			if limited := spendGuestBudget(WithEnvelopeFacts(ctx, facts), d, ChargeGuest); limited != nil {
				return d.sealLimited(ctx, facts, limited)
			}
			d.audit(actorOf(facts), "sealed_call", "account:"+d.AccountID, facts.Refusal)
			return d.sealedCode(ctx, facts, facts.Refusal), nil
		}
		if facts.Tier == TierPendingAddress {
			// PACT §5.3 under `ask`, or a root returned after a removal: the
			// update_contact that brought the new address answers pending, and
			// every other call from that address, until the owner decides,
			// answers pending_approval — nothing runs either way.
			if limited := spendGuestBudget(WithEnvelopeFacts(ctx, facts), d, ChargeGuest); limited != nil {
				return d.sealLimited(ctx, facts, limited)
			}
			d.audit(actorOf(facts), "sealed_call", "account:"+d.AccountID+" contact:"+facts.From, "pending_new_address")
			if toolNameOf(facts.Payload) == "update_contact" {
				// The same tool result the plaintext gate answers (servers.go), sealed. This sealed
				// the bare object `{"status":"pending"}` instead — not a tool result at all — so a
				// caller that sealed its announcement decoded an answer with no content and could
				// not see that it was pending. Nothing caught it: the one test of this exchange
				// reached it in plaintext, by passing a nil key to a `Call` that downgraded.
				pending, err := json.Marshal(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"pending"}`}}})
				if err != nil {
					return d.sealedCode(ctx, facts, "unavailable"), nil
				}
				return d.sealBack(ctx, facts, pending)
			}
			return d.sealedCode(ctx, facts, "pending_approval"), nil
		}
		// Envelope-level idempotency (§4.4 step 8): a replay is acknowledged
		// with its recorded result, never re-executed.
		if ack, replayed, err := d.Identifier.Replay(ctx, d.Idem, d.AccountID, facts); err == nil && replayed {
			return d.sealBack(ctx, facts, json.RawMessage(ack))
		}
		// The budget, after the replay (a replay spends nothing) and before the dispatch looks for
		// anything: every inner call spends — `tools/list`, and a tool the caller may not see or
		// that does not exist, as much as one it may call (PACT §12; the cloud's surface spends at
		// the same point). A refusal is sealed back and NOT recorded as the envelope's answer: the
		// reservation Replay made stays empty, so the same envelope sent again once the budget
		// holds a call is served rather than answered rate_limited from the record. It is sealed as
		// a tool error inside `result`, where a guarded refusal has always been and where the
		// client keeps `retry_after` (an `error` member is reduced to its code), as the cloud seals it.
		if r := d.Pool.spend(WithEnvelopeFacts(ctx, facts)); r != nil {
			d.audit(actorOf(facts), "sealed_call", "account:"+d.AccountID+" contact:"+facts.From, r.Code())
			return d.sealLimited(ctx, facts, r.Result())
		}
		// Handlers see the envelope's facts exactly as they see transport facts,
		// so a guest tool can pin the key the envelope proved (§5.3).
		inner, err := d.Pool.Dispatch(WithEnvelopeFacts(ctx, facts), d.AccountID, facts.From, facts.Payload)
		if err != nil {
			// The envelope opened, so the caller's key is in hand — and §13.2
			// says errors follow the sealing rule once it is: a plaintext error
			// here would leak the failure shape to whatever carried the call.
			// Plaintext errors are only for envelopes that could not be opened.
			d.audit(actorOf(facts), "sealed_call", "account:"+d.AccountID+" contact:"+facts.From, "unavailable")
			if inner, merr := json.Marshal(codeResult("unavailable")); merr == nil {
				return d.sealBack(ctx, facts, inner)
			}
			return errEnvelope("unavailable"), nil
		}
		if d.Idem != nil && facts.Header.MsgID != "" {
			if u, ok := d.Idem.(interface {
				UpdateIdempotencyAck(ctx context.Context, accountID, contactFpr, msgID, ack string) error
			}); ok {
				_ = u.UpdateIdempotencyAck(ctx, d.AccountID, facts.From, EnvelopeKey(facts.Header.MsgID), string(inner))
			}
		}
		d.audit(actorOf(facts), "sealed_call", "account:"+d.AccountID+" contact:"+facts.From, "ok")
		return d.sealBack(ctx, facts, inner)
	}
}

// sealLimited seals a budget's refusal as a tool error inside `result`, where the client keeps its
// `retry_after`; an `error` member is reduced to its code (PACT §12, as the cloud seals it).
//
// A refusal that cannot be sealed goes out as itself, in the clear (sealBackErr says when), never
// as another code.
func (d SealedDeps) sealLimited(ctx context.Context, facts *EnvelopeFacts, limited *mcp.CallToolResult) (*mcp.CallToolResult, error) {
	body, err := json.Marshal(limited)
	if err != nil {
		return limited, nil
	}
	res, err := d.sealResult(ctx, facts, body, false)
	if err != nil {
		return limited, nil
	}
	return res, nil
}

// sealBack seals the inner result to the caller (PACT §13.2: a sealed request
// MUST get a sealed result — same format, the request's msg_id). A result is never sent in the
// clear: one that cannot be sealed is answered `unavailable`.
func (d SealedDeps) sealBack(ctx context.Context, facts *EnvelopeFacts, inner json.RawMessage) (*mcp.CallToolResult, error) {
	res, err := d.sealResult(ctx, facts, inner, false)
	if err != nil {
		return errEnvelope("unavailable"), nil
	}
	return res, nil
}

// sealBackErr seals a wrapper-level refusal — one of §12's codes, in §13.2's
// `error` form.
//
// PACT §13.2: "once a request envelope has been successfully opened, an error
// result MUST be sealed back like any other result — a plaintext error is only
// for an envelope that could not be opened at all, where there is no proven key
// to seal toward." Past the open there IS a proven key, so the only reason to
// answer in the clear is not having thought about it.
//
// It is not a formality. `pending_approval` in plaintext tells whatever carried
// the call that this sender is one the recipient PINS — a stranger's envelope
// never produces it — so the carrier separates "someone the recipient knows,
// calling from an address not yet approved" from "a stranger", by reading an
// answer it was never meant to be able to read. That correlation is precisely
// what sealing denies it (PACT §13.5, §12).
//
// Plaintext past the open is for one case: there is no key to seal to — the facts name no caller's
// key, or this identity holds no current key and chain to answer under — or the seal itself fails.
// The refusal then goes out as itself: the caller cannot be answered at all otherwise, and the code
// it is owed beats another. Every path that reaches here names the caller's key: an `ok` decision
// names the leaf that signed, and a `pending_approval` is sealed to the leaf decideEnvelope reads
// with signerOf (pact-identity's Decide answers that code with no leaf of its own). A facts with no
// key is signerOf finding no `pending_out` pin for the proof, which Decide's answer rules out.
func (d SealedDeps) sealBackErr(ctx context.Context, facts *EnvelopeFacts, body json.RawMessage) *mcp.CallToolResult {
	res, err := d.sealResult(ctx, facts, body, true)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}
	}
	return res
}

// sealedCode is sealBackErr for a bare §12 code.
func (d SealedDeps) sealedCode(ctx context.Context, facts *EnvelopeFacts, code string) *mcp.CallToolResult {
	return d.sealBackErr(ctx, facts, json.RawMessage(`{"code":`+strconv.Quote(code)+`}`))
}

// sealResult seals a result to a 2.0 caller (PACT §13.2): kid names the
// caller's leaf key, the plaintext carries our chain until this contact has
// seen our current leaf and our leaf's fingerprint after, and the result rides
// beside it. A guest always gets the chain: nothing records what it has seen.
//
// It seals under the state the open was decided against (EnvelopeFacts.state), which every facts
// decideEnvelope returns carries. It read the state again here — the account row, the chain, every
// held key decrypted and parsed — on every sealed answer, for the one key it uses.
//
// An answer it cannot seal is an error, and the caller decides what goes out instead: a result is
// answered `unavailable` (sealBack), a refusal goes as itself (sealBackErr, sealLimited).
func (d SealedDeps) sealResult(ctx context.Context, facts *EnvelopeFacts, inner json.RawMessage, asError bool) (*mcp.CallToolResult, error) {
	st := facts.state
	key := (*identity.LeafKey)(nil)
	if st != nil {
		key = st.current()
	}
	if key == nil || key.Lib == nil || len(st.Chain) != 2 {
		return nil, errors.New("seal: no current key and chain to answer under")
	}
	sender := key.Lib
	recipient, err := pactidentity.ParseSPKI(facts.SPKI)
	if err != nil {
		return nil, fmt.Errorf("seal: the caller's key is not in hand: %w", err)
	}
	ourKid := key.KP.Fingerprint
	form, pinned := "chain", false
	if !facts.Guest && !facts.Demote && facts.From != "" {
		if c, err := d.Identifier.Store.GetContact(ctx, d.AccountID, facts.From); err == nil {
			pinned = true
			if c.ChainSentKid == ourKid {
				form = "leaf"
			}
		}
	}
	now := d.now()
	opts := pactidentity.SealOpts{
		RecipientKey: recipient, Sender: sender, Form: form, SenderChain: st.Chain, Result: json.RawMessage(inner),
		MsgID: facts.Header.MsgID, TS: now.Unix(), Exp: now.Add(ResultLifetime).Unix(),
	}
	if asError {
		// §13.2's result plaintext is `result` OR `error`, never both.
		opts.Result, opts.Error = nil, json.RawMessage(inner)
	}
	out, err := pactidentity.SealResult(opts)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if pinned && form == "chain" {
		_ = d.Identifier.Store.SetContactChainSentKid(ctx, d.AccountID, facts.From, ourKid)
	}
	body, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
}

// Dispatch runs one inner request against the caller's composed surface. It is
// the sealed path's equivalent of an MCP request arriving directly: the same
// registry, the same policy.Allow, the same call-time re-check (SPEC §4.5).
// The caller's budget is spent before this is called (sealedHandler), not here.
func (p *Pool) Dispatch(ctx context.Context, accountID, fpr string, pay Payload) (json.RawMessage, error) {
	caller, err := p.resolveCaller(ctx, accountID, fpr)
	if err != nil {
		return nil, err
	}
	switch pay.Method {
	case "tools/list":
		tools := make([]*mcp.Tool, 0, 8)
		for _, e := range p.Registry.snapshot() {
			if policy.Allow(caller, e.Rule) {
				tools = append(tools, e.Tool)
			}
		}
		return json.Marshal(map[string]any{"tools": tools})
	case "tools/call":
		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(pay.Params, &call); err != nil {
			return nil, fmt.Errorf("%w: inner params", envelope.ErrInvalid)
		}
		for _, e := range p.Registry.snapshot() {
			if e.Tool.Name != call.Name {
				continue
			}
			// checked() re-checks policy.Allow at call time — a sealed call gets
			// no weaker gate than a direct one. The budget was spent before Dispatch.
			res, err := p.checked(accountID, fpr, e)(ctx, &mcp.CallToolRequest{
				Params: &mcp.CallToolParamsRaw{Name: call.Name, Arguments: call.Arguments},
			})
			if err != nil {
				return nil, err
			}
			return json.Marshal(res)
		}
		// A tool the caller may not see is indistinguishable from one that does
		// not exist (§5.4), and at guest tier that answer is `blocked_or_unknown`
		// — the same one a blocked caller gets, which is the point.
		code := refusalCode(caller.Tier)
		p.audit(caller.Tier, "tools_call", "caller:"+fprOrAnonymous(fpr)+" tool:"+call.Name, code)
		return json.Marshal(codeResult(code))
	default:
		return nil, fmt.Errorf("%w: inner method %q", envelope.ErrInvalid, pay.Method)
	}
}

// toolNameOf reads the inner call's tool name, "" for tools/list or a
// payload with none.
func toolNameOf(p Payload) string {
	if p.Method != "tools/call" || len(p.Params) == 0 {
		return ""
	}
	var params struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(p.Params, &params)
	return params.Name
}

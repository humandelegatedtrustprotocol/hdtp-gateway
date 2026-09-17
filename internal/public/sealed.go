package public

// `sealed_call` (SPEC §4.5, PACT §13.2): the one wrapper tool that carries
// sealing MCP-natively. It is present at EVERY tier — guest, pending, contact —
// so it is registered once per tier and exactly one entry matches any caller.
//
// The inner request is dispatched against the caller's own composed surface
// through the SAME policy path a direct call takes (Pool.Dispatch → guarded →
// policy.Allow), using the identity the envelope proved — which in edge and
// relay-assisted mode is the only identity there is. The result is sealed back
// to that caller: a sealed request gets a sealed result, always.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
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
	AccountFpr string
	// Keypair unseals the account identity key (to open and to sign results).
	Keypair func(ctx context.Context) (*identity.Keypair, error)
	// Idem is optional; nil disables envelope-level msg_id replay.
	Idem IdempotencyStore
	// Delivery marks how envelopes reach this surface (relay fetch = DeliveryRelay).
	Delivery Delivery
	Now      func() time.Time
	Audit    func(action, resource, outcome string)
}

func (d SealedDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d SealedDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
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
func spendGuestBudget(ctx context.Context, d SealedDeps) *mcp.CallToolResult {
	if d.Pool == nil || d.Pool.Limit == nil {
		return nil
	}
	ok, retry := d.Pool.Limit(ctx)
	if ok {
		return nil
	}
	d.audit("sealed_call", "account:"+d.AccountID, "rate_limited")
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{
		&mcp.TextContent{Text: fmt.Sprintf(`{"code":"rate_limited","retry_after":%d}`, int(retry.Seconds())+1)},
	}}
}

func sealedHandler(d SealedDeps) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var env envelope.Envelope
		if err := json.Unmarshal(req.Params.Arguments, &env); err != nil {
			return errEnvelope("envelope_invalid"), nil
		}
		facts, err := d.Identifier.OpenSealed(ctx, d.AccountID, d.AccountFpr, FactsFrom(ctx), &env, d.Delivery)
		if err != nil {
			var renewed *CertificateRenewed
			switch {
			case errors.Is(err, ErrChainRequired):
				// PACT §14.5: a guessed fingerprint spends the source's guest
				// budget. The wrapper is exempt from the per-call budget (see
				// guarded), so this answer charges it here, as a guest.
				if limited := spendGuestBudget(ctx, d); limited != nil {
					return limited, nil
				}
			case errors.As(err, &renewed):
				// PACT §14.4: plaintext, carrying the current chain — proof of
				// nothing by itself; the caller validates it to its own pin.
				d.audit("sealed_call", "account:"+d.AccountID, "certificate_renewed")
				chain := make([]string, 0, len(renewed.Chain))
				for _, c := range renewed.Chain {
					chain = append(chain, b64u(c))
				}
				body, _ := json.Marshal(map[string]any{"code": "certificate_renewed", "data": map[string]any{"chain": chain}})
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
			}
			d.audit("sealed_call", "account:"+d.AccountID, Code(err))
			return errEnvelope(Code(err)), nil
		}
		if facts.Refusal != "" {
			// A pinned root at an address the owner has not approved (PACT
			// §5.3): the seed's plain code, nothing dispatched — and charged, so
			// a host calling from an unapproved address cannot do it for free.
			if limited := spendGuestBudget(ctx, d); limited != nil {
				return limited, nil
			}
			d.audit("sealed_call", "account:"+d.AccountID, facts.Refusal)
			return errEnvelope(facts.Refusal), nil
		}
		if facts.Tier == TierPendingAddress {
			// PACT §5.3 under `ask`, or a root returned after a removal: the
			// update_contact that brought the new address answers pending, and
			// every other call from that address, until the owner decides,
			// answers pending_approval — nothing runs either way.
			if limited := spendGuestBudget(ctx, d); limited != nil {
				return limited, nil
			}
			d.audit("sealed_call", "account:"+d.AccountID+" contact:"+facts.From, "pending_new_address")
			if toolNameOf(facts.Payload) == "update_contact" {
				return d.sealBack(ctx, facts, json.RawMessage(`{"status":"pending"}`))
			}
			return errEnvelope("pending_approval"), nil
		}
		// Envelope-level idempotency (§4.4 step 8): a replay is acknowledged
		// with its recorded result, never re-executed.
		if ack, replayed, err := d.Identifier.Replay(ctx, d.Idem, d.AccountID, facts); err == nil && replayed {
			return d.sealBack(ctx, facts, json.RawMessage(ack))
		}
		// Handlers see the envelope's facts exactly as they see transport facts,
		// so a guest tool can pin the key the envelope proved (§5.3).
		inner, err := d.Pool.Dispatch(WithEnvelopeFacts(ctx, facts), d.AccountID, facts.From, facts.Payload)
		if err != nil {
			// The envelope opened, so the caller's key is in hand — and §13.2
			// says errors follow the sealing rule once it is: a plaintext error
			// here would leak the failure shape to whatever carried the call.
			// Plaintext errors are only for envelopes that could not be opened.
			d.audit("sealed_call", "account:"+d.AccountID+" contact:"+facts.From, "unavailable")
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
		d.audit("sealed_call", "account:"+d.AccountID+" contact:"+facts.From, "ok")
		return d.sealBack(ctx, facts, inner)
	}
}

// sealBack seals the inner result to the caller (PACT §13.2: a sealed request
// MUST get a sealed result — same format, the request's msg_id).
func (d SealedDeps) sealBack(ctx context.Context, facts *EnvelopeFacts, inner json.RawMessage) (*mcp.CallToolResult, error) {
	return d.sealBack20(ctx, facts, inner)
}

// sealBack20 seals a result to a 2.0 caller (PACT §13.2): kid names the
// caller's leaf key, the plaintext carries our chain until this contact has
// seen our current leaf and our leaf's fingerprint after, and the result rides
// beside it. A guest always gets the chain: nothing records what it has seen.
func (d SealedDeps) sealBack20(ctx context.Context, facts *EnvelopeFacts, inner json.RawMessage) (*mcp.CallToolResult, error) {
	st, err := d.Identifier.State20(ctx)
	if err != nil || st == nil || st.currentKey() == nil || len(st.Chain) != 2 {
		return errEnvelope("unavailable"), nil
	}
	sender, err := identity.ToLib(st.currentKey())
	if err != nil {
		return errEnvelope("unavailable"), nil
	}
	recipient, err := pactidentity.ParseSPKI(facts.SPKI)
	if err != nil {
		return errEnvelope("envelope_invalid"), nil
	}
	ourKid := st.currentKey().Fingerprint
	form, pinned := "chain", false
	if !facts.Guest && !facts.Demote && facts.From != "" {
		if c, err := d.Identifier.Store.GetContact(ctx, d.AccountID, facts.From); err == nil && c.Protocol == 2 {
			pinned = true
			if c.ChainSentKid == ourKid {
				form = "leaf"
			}
		}
	}
	now := d.now()
	out, err := pactidentity.SealResult(pactidentity.SealOpts{
		RecipientKey: recipient, Sender: sender, Form: form, SenderChain: st.Chain, Result: json.RawMessage(inner),
		MsgID: facts.Header.MsgID, TS: now.Unix(), Exp: now.Add(ResultLifetime).Unix(),
	})
	if err != nil {
		return errEnvelope("unavailable"), nil
	}
	if pinned && form == "chain" {
		_ = d.Identifier.Store.SetContactChainSentKid(ctx, d.AccountID, facts.From, ourKid)
	}
	body, err := json.Marshal(out)
	if err != nil {
		return errEnvelope("unavailable"), nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
}

// Dispatch runs one inner request against the caller's composed surface. It is
// the sealed path's equivalent of an MCP request arriving directly: the same
// registry, the same policy.Allow, the same call-time re-check (SPEC §4.5).
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
			// guarded() re-checks policy.Allow at call time — a sealed call gets
			// no weaker gate than a direct one.
			res, err := p.guarded(accountID, fpr, e)(ctx, &mcp.CallToolRequest{
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

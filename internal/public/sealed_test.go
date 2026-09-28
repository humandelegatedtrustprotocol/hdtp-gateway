package public

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/policy"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// The `sealed_call` wrapper: what it is present at, what it lets through, what it
// spends, and what it seals back.
//
// This replaces `sealed_test.go`, which proved the same nine things by building
// `v: 1` envelopes. The wrapper's behaviour was never generation-specific — tier
// gating, replay, the guest budget and the seal policy are the same rules either
// way — so the tests are the same tests over the envelope that still exists.

// sealedEnv is recvEnv plus the registry, pool and SealedDeps that `serve` composes.
type sealedEnv struct {
	*recvEnv
	pool *Pool
	deps SealedDeps
}

func echoTool(name string, tier policy.Tier, perm string) Entry {
	return Entry{
		Tool: &mcp.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
		Rule: policy.Rule{Tier: tier, Permission: perm},
		Handler: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran:" + name}}}, nil
		},
	}
}

func newSealedEnv(t testing.TB) *sealedEnv {
	t.Helper()
	e := newRecvEnv(t)
	reg := &Registry{}
	reg.Add(
		echoTool("redeem_invite", policy.TierGuest, ""),
		echoTool("request_contact", policy.TierGuest, ""),
		echoTool("get_card", policy.TierContact, ""),
		echoTool("send_message", policy.TierContact, "message.text"),
		echoTool("book_slot", policy.TierContact, "calendar.book"),
	)
	pool := NewPool(reg, StoreResolver(e.st), 8)
	deps := SealedDeps{
		Pool: pool, Identifier: e.id, AccountID: e.acct.ID,
		Keypair: func(ctx context.Context) (*identity.Keypair, error) { return e.keypair(ctx) },
		Idem:    e.st, Now: func() time.Time { return e.nowAt },
	}
	reg.Add(SealedEntries(deps)...)
	return &sealedEnv{recvEnv: e, pool: pool, deps: deps}
}

// call invokes sealed_call the way an MCP server would.
func (s *sealedEnv) call(t testing.TB, env *pactidentity.Envelope, tf TransportFacts) *mcp.CallToolResult {
	t.Helper()
	args, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), factsKey{}, tf)
	res, err := sealedHandler(s.deps)(ctx, &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: SealedToolName, Arguments: args},
	})
	if err != nil {
		t.Fatalf("sealed_call returned a transport error rather than a result: %v", err)
	}
	return res
}

// text is the answer's payload, sealed or plaintext, as a string.
func text(t testing.TB, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatal("no content in the result")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, not text", res.Content[0])
	}
	return tc.Text
}

// msgIDFor mirrors what sealFrom stamps on a request, so a result can be correlated.
func msgIDFor(tool, form string) string { return "m-" + tool + "-" + form }

// opened unseals the answer to a peer and reports the inner result and error.
func (s *sealedEnv) opened(t testing.TB, res *mcp.CallToolResult, p *peer, tool string) (result, errObj json.RawMessage) {
	t.Helper()
	if res.IsError {
		t.Fatalf("a refusal that could be sealed came back in plaintext: %s", text(t, res))
	}
	var wire pactidentity.Envelope
	if err := json.Unmarshal([]byte(text(t, res)), &wire); err != nil {
		t.Fatalf("the answer is not an envelope: %v (%s)", err, text(t, res))
	}
	st, err := s.state(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := pactidentity.OpenResult(wire, pactidentity.OpenOpts{
		Recipient: p.host, RecipientPublic: p.host.Public(), MsgID: msgIDFor(tool, "chain"), Now: s.nowAt,
		Pins: []pactidentity.Pin{{
			Root: s.root.fpr, Endpoint: endpointMe,
			Leaf: pactidentity.B64url(st.Chain[0]), State: "active",
		}},
		ExpectedRoot: s.root.fpr,
	})
	if err != nil {
		t.Fatalf("the answer did not open: %v", err)
	}
	return out.Result, out.Error
}

func TestSealedCallIsPresentAtEveryTier(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	guestPeer := newPeer(t, s.nowAt)
	pendingPeer := newPeer(t, s.nowAt)
	contactPeer := newPeer(t, s.nowAt)
	s.pin(t, pendingPeer, "pending_in")
	s.pin(t, contactPeer, "active")

	for _, p := range []*peer{guestPeer, pendingPeer, contactPeer} {
		srv, err := s.pool.ServerFor(ctx, s.acct.ID, p.fpr())
		if err != nil {
			t.Fatal(err)
		}
		ct, st := mcp.NewInMemoryTransports()
		if _, err := srv.Connect(ctx, st, nil); err != nil {
			t.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "peer", Version: "0"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		list, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, tl := range list.Tools {
			if tl.Name == SealedToolName {
				seen++
			}
		}
		cs.Close()
		if seen != 1 {
			t.Fatalf("%s sees sealed_call %d times, want exactly 1", p.fpr(), seen)
		}
	}
}

func TestSealedGuestReachesGuestToolsOnly(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	// A guest's sealed call must carry the card it is binding to.
	env := s.sealFrom(t, p, "chain", "redeem_invite", map[string]any{"card": cardOf(p)})
	if got, _ := s.opened(t, s.call(t, env, TransportFacts{}), p, "redeem_invite"); got == nil {
		t.Error("a guest could not reach redeem_invite")
	}
	// A guest's sealed call may only redeem or request (PACT §13.2). Anything else
	// fails the guest binding, which happens BEFORE the envelope is dispatched — so
	// the refusal is plaintext, with no proven key to seal toward.
	env = s.sealFrom(t, p, "chain", "send_message", map[string]any{"card": cardOf(p)})
	res := s.call(t, env, TransportFacts{})
	if !res.IsError || !strings.Contains(text(t, res), "envelope_invalid") {
		t.Errorf("a guest reached a contact tool: %s", text(t, res))
	}
}

func TestPlaintextToSealRequiredAccountRefused(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	s.pin(t, p, "active")
	ctx := context.Background()

	// With no identity at all, identity_required comes FIRST — PACT §13.3 orders
	// the two, and the order is the point: a caller is told what it lacks in the
	// order the receiver checks, not the order that happens to fail.
	if _, err := s.id.PlaintextGateCtx(ctx, TransportFacts{}, "send_message", true); err == nil ||
		!strings.Contains(err.Error(), "identity") {
		t.Fatalf("a plaintext call with no identity: %v", err)
	}

	// With an identity, the seal policy is what refuses it.
	leaf, _ := pactidentity.Parse(p.leaf)
	tf := TransportFacts{
		ClientCertFingerprint: p.fpr(), ClientCertSPKI: leaf.SPKI,
		ClientLeaf: p.leaf, ClientEndpoint: endpointA,
	}
	if _, err := s.id.PlaintextGateCtx(ctx, tf, "send_message", true); err == nil ||
		!strings.Contains(err.Error(), "seal") {
		t.Fatalf("a plaintext substantive call to a seal=required account: %v", err)
	}
}

func TestSealedReplayReturnsRecordedResult(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	s.pin(t, p, "active")
	env := s.sealFrom(t, p, "chain", "send_message", map[string]any{})
	first, _ := s.opened(t, s.call(t, env, TransportFacts{}), p, "send_message")
	second, _ := s.opened(t, s.call(t, env, TransportFacts{}), p, "send_message")
	if string(first) != string(second) {
		t.Errorf("a replayed envelope was not acknowledged with its original result:\n%s\n%s", first, second)
	}
}

func TestSealNoneRefusesEnvelopes(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	s.pin(t, p, "active")
	s.id.Seal = core.SealNone
	env := s.sealFrom(t, p, "chain", "send_message", map[string]any{})
	res := s.call(t, env, TransportFacts{})
	if !res.IsError || !strings.Contains(text(t, res), "seal_not_accepted") {
		t.Fatalf("an envelope to a seal=none account: %s", text(t, res))
	}
}

func TestAnEmptyMsgIDIsInvalid(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	s.pin(t, p, "active")
	env := s.sealFrom(t, p, "chain", "send_message", map[string]any{},
		func(o *pactidentity.SealOpts) { o.MsgID = "" })
	res := s.call(t, env, TransportFacts{})
	if !res.IsError || !strings.Contains(text(t, res), "envelope_invalid") {
		t.Fatalf("an envelope with no msg_id: %s", text(t, res))
	}
}

func TestDispatchErrorsAreSealedBack(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	s.pin(t, p, "active")
	// book_slot needs calendar.book, which pin() does not grant.
	env := s.sealFrom(t, p, "chain", "book_slot", map[string]any{})
	// The refusal is the inner tool's answer, so it rides back inside the sealed
	// result as an isError CallToolResult — not as the envelope's own error member,
	// which is for failures the envelope layer itself produced.
	out, _ := s.opened(t, s.call(t, env, TransportFacts{}), p, "book_slot")
	if !strings.Contains(string(out), "permission_denied") {
		t.Errorf("a permission refusal was not sealed back: %s", out)
	}
}

// A sealed_call whose members are not base64url is an envelope that cannot be opened, like any
// other: it is answered envelope_invalid and audited once as a sealed_call refusal, and under
// seal=none it is answered seal_not_accepted, as every envelope is. The node used to decode the
// members itself before the open, and answered this one early — unaudited, and envelope_invalid
// whatever the seal policy said.
func TestAnUnreadableEnvelopeIsRefusedLikeAnyOther(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt)
	s.pin(t, p, "active")
	var rows []string
	s.deps.Audit = func(action, resource, outcome string) { rows = append(rows, action+" "+outcome) }
	raw := func(args string) *mcp.CallToolResult {
		t.Helper()
		ctx := context.WithValue(context.Background(), factsKey{}, TransportFacts{})
		res, err := sealedHandler(s.deps)(ctx, &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Name: SealedToolName, Arguments: json.RawMessage(args)},
		})
		if err != nil {
			t.Fatalf("sealed_call returned a transport error rather than a result: %v", err)
		}
		return res
	}
	if res := s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "hi"}), TransportFacts{}); res.IsError {
		t.Fatalf("the control, a well-formed envelope from a contact, must get through: %s", text(t, res))
	}
	const unreadable = `{"protected":"!!!","enc":"AA","ct":"AA","sig":"AA"}`
	rows = nil
	if res := raw(unreadable); !res.IsError || !strings.Contains(text(t, res), `"envelope_invalid"`) {
		t.Fatalf("members that are not base64url: %s", text(t, res))
	}
	if len(rows) != 1 || rows[0] != "sealed_call envelope_invalid" {
		t.Fatalf("the refusal must be audited once, as a sealed_call refusal; audited %q", rows)
	}
	s.id.Seal = core.SealNone
	if res := raw(unreadable); !res.IsError || !strings.Contains(text(t, res), "seal_not_accepted") {
		t.Fatalf("under seal=none, members that are not base64url: %s", text(t, res))
	}
}

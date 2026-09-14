package public

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// sealed20Env wires the real built-in tools, a pool with a counting budget,
// and the sealed_call wrapper over a 2.0 account — the shape serve composes.
type sealed20Env struct {
	*env20
	pool    *Pool
	deps    SealedDeps
	cm      *contacts.Manager
	charged int
}

func newSealed20Env(t *testing.T) *sealed20Env {
	t.Helper()
	e := newEnv20(t)
	cm := &contacts.Manager{Store: e.st, Now: func() time.Time { return e.nowAt }}
	reg := &Registry{}
	s := &sealed20Env{env20: e, cm: cm}
	reg.Add(BuiltinEntries(ToolDeps{
		AccountID: e.acct.ID, Contacts: cm,
		Card: func(ctx context.Context) (string, string, []byte, error) {
			chain, err := e.m.Chain(ctx, e.acct.ID)
			if err != nil {
				return "", "", nil, err
			}
			spki, _ := identity.SPKI(e.currentKey(t))
			return contacts.BuildCard20("Me", chain[0], "required"), "", spki, nil
		},
		Endpoint: func() string { return endpointMe },
	})...)
	s.pool = NewPool(reg, StoreResolver(e.st), 8)
	s.pool.Limit = func(context.Context) (bool, time.Duration) { s.charged++; return s.charged <= 3, time.Minute }
	s.deps = SealedDeps{
		Pool: s.pool, Identifier: e.id, AccountID: e.acct.ID, AccountFpr: e.acct.Fingerprint,
		Keypair: func(ctx context.Context) (*identity.Keypair, error) { return e.id.Keypair(ctx, e.acct.ID) },
		Idem:    e.st, Now: func() time.Time { return e.nowAt },
	}
	reg.Add(SealedEntries(s.deps)...)
	return s
}

func (s *sealed20Env) call(t *testing.T, env *envelope.Envelope) *mcp.CallToolResult {
	t.Helper()
	args, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), factsKey{}, TransportFacts{RemoteIP: "203.0.113.9"})
	res, err := sealedHandler(s.deps)(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: SealedToolName, Arguments: args}})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res
}

func text(res *mcp.CallToolResult) string { return res.Content[0].(*mcp.TextContent).Text }

// openResult opens a `v: 2` result at the peer, as its own node would (§13.2).
func (s *sealed20Env) openResult(t *testing.T, res *mcp.CallToolResult, p *peer, msgID string, pinned ...[]byte) *pactidentity.Opened {
	t.Helper()
	if res.IsError {
		t.Fatalf("wrapper error: %s", text(res))
	}
	var out pactidentity.Envelope
	if err := json.Unmarshal([]byte(text(res)), &out); err != nil {
		t.Fatal(err)
	}
	chain, _ := s.m.Chain(context.Background(), s.acct.ID)
	held := chain[0]
	if len(pinned) > 0 {
		held = pinned[0] // what the peer held before we renewed
	}
	opened, err := pactidentity.OpenResult(out, pactidentity.OpenOpts{
		Recipient: p.host, MsgID: msgID, Now: s.nowAt,
		Pins:         []pactidentity.Pin{{Root: s.acct.RootFingerprint, Endpoint: endpointMe, Leaf: pactidentity.B64url(held), State: "active"}},
		ExpectedRoot: s.acct.RootFingerprint, ExpectedEndpoint: endpointMe,
	})
	if err != nil {
		t.Fatalf("the result does not open at the peer: %v", err)
	}
	return opened
}

func TestSealed20ChainRequiredSpendsTheGuestBudget(t *testing.T) {
	s := newSealed20Env(t)
	stranger := newPeer(t, fixedNow)
	for i := 0; i < 3; i++ {
		res := s.call(t, s.seal20(t, stranger, "leaf", "send_message", nil, func(o *pactidentity.SealOpts) { o.MsgID = "guess-" + string(rune('a'+i)) }))
		if !res.IsError || text(res) != `{"code":"chain_required"}` {
			t.Fatalf("guess %d: %s", i, text(res))
		}
	}
	if s.charged != 3 {
		t.Fatalf("each guess must spend a guest unit: %d", s.charged)
	}
	res := s.call(t, s.seal20(t, stranger, "leaf", "send_message", nil, func(o *pactidentity.SealOpts) { o.MsgID = "guess-z" }))
	if !strings.Contains(text(res), `"rate_limited"`) {
		t.Fatalf("over budget: %s", text(res))
	}
}

func TestSealed20StaleKidGetsTheChainInPlaintext(t *testing.T) {
	s := newSealed20Env(t)
	p := newPeer(t, fixedNow)
	s.pin(t, p, "active")
	env := s.seal20(t, p, "leaf", "send_message", nil)
	s.nowAt = fixedNow.Add(time.Hour)
	s.install(t, identity.PurposeRenew, endpointMe)
	// The old leaf expires an hour before the new one does: in that hour the
	// kid is former and the current chain still validates.
	s.nowAt = fixedNow.Add(365*24*time.Hour - 30*time.Minute)
	res := s.call(t, env)
	var answer struct {
		Code string `json:"code"`
		Data struct {
			Chain []string `json:"chain"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(text(res)), &answer); err != nil || answer.Code != "certificate_renewed" || len(answer.Data.Chain) != 2 {
		t.Fatalf("stale kid: %s", text(res))
	}
	// The caller validates it to the root it pinned and the address it dialed (§14.4).
	chain := [][]byte{pactidentity.FromB64url(answer.Data.Chain[0]), pactidentity.FromB64url(answer.Data.Chain[1])}
	if vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: s.nowAt, ExpectedRoot: s.acct.RootFingerprint, ExpectedEndpoint: endpointMe}); !vr.OK {
		t.Fatalf("the chain in the answer does not validate: rule %d %s", vr.Rule, vr.Reason)
	}
}

func TestSealed20ResultCarriesTheChainOnceThenTheFingerprint(t *testing.T) {
	s := newSealed20Env(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	s.pin(t, p, "active")
	first := s.openResult(t, s.call(t, s.seal20(t, p, "chain", "get_card", nil, func(o *pactidentity.SealOpts) { o.MsgID = "r1" })), p, "r1")
	if first.Form != "chain" || first.Root != s.acct.RootFingerprint || first.Result == nil {
		t.Fatalf("first result: %+v", first)
	}
	if c, _ := s.st.GetContact(ctx, s.acct.ID, p.fpr()); c.ChainSentKid != s.acct.Fingerprint {
		t.Fatalf("the chain-sent mark was not recorded: %+v", c)
	}
	second := s.openResult(t, s.call(t, s.seal20(t, p, "leaf", "get_card", nil, func(o *pactidentity.SealOpts) { o.MsgID = "r2" })), p, "r2")
	if second.Form != "leaf" {
		t.Fatalf("second result must name the leaf by fingerprint: %+v", second)
	}
	var card struct {
		Card string `json:"card"`
	}
	var mcpRes struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(second.Result, &mcpRes); err != nil || len(mcpRes.Content) != 1 {
		t.Fatalf("result shape: %s", second.Result)
	}
	if err := json.Unmarshal([]byte(mcpRes.Content[0].Text), &card); err != nil || !strings.Contains(card.Card, "X-PACT-CERT:") {
		t.Fatalf("get_card must return the 2.0 card: %s", mcpRes.Content[0].Text)
	}
	// A renewal clears the mark: the next result carries the chain again, and
	// a peer still holding the old leaf learns the new one from it.
	before, _ := s.m.Chain(ctx, s.acct.ID)
	s.nowAt = fixedNow.Add(time.Hour)
	s.install(t, identity.PurposeRenew, endpointMe)
	third := s.openResult(t, s.call(t, s.seal20(t, p, "leaf", "get_card", nil, func(o *pactidentity.SealOpts) { o.MsgID = "r3" })), p, "r3", before[0])
	if third.Form != "chain" || third.LeafUpdate == nil {
		t.Fatalf("after a renewal the chain rides once more and the peer learns the leaf: %+v", third)
	}
}

func TestSealed20GuestRedeemsAndIsPinnedByRoot(t *testing.T) {
	s := newSealed20Env(t)
	ctx := context.Background()
	token, _, err := s.cm.CreateInvite(ctx, s.acct.ID, contacts.InviteOptions{AutoAccept: true, Preset: "basic"})
	if err != nil {
		t.Fatal(err)
	}
	p := newPeer(t, fixedNow)
	res := s.call(t, s.seal20(t, p, "chain", "redeem_invite", map[string]any{"token": token, "card": card20(p)}, func(o *pactidentity.SealOpts) { o.MsgID = "redeem" }))
	opened := s.openResult(t, res, p, "redeem")
	if !strings.Contains(string(opened.Result), `\"status\":\"accepted\"`) && !strings.Contains(string(opened.Result), `"status":"accepted"`) {
		t.Fatalf("redeem: %s", opened.Result)
	}
	c, err := s.st.GetContact(ctx, s.acct.ID, p.fpr())
	if err != nil || c.Protocol != 2 || c.Status != "active" || c.Endpoint != endpointA || string(c.Leaf) != string(p.leaf) {
		t.Fatalf("the guest was not pinned by its root: %v %+v", err, c)
	}
	leaf, _ := pactidentity.Parse(p.leaf)
	if string(c.SPKI) != string(leaf.SPKI) {
		t.Fatal("the pinned key must be the leaf's")
	}
	// Now a contact: the small form works, and a blocked contact's chain is a stranger's.
	if r := s.openResult(t, s.call(t, s.seal20(t, p, "leaf", "get_card", nil, func(o *pactidentity.SealOpts) { o.MsgID = "after" })), p, "after"); r.Result == nil {
		t.Fatal("no result")
	}
	if err := s.st.UpdateContactStatus(ctx, s.acct.ID, p.fpr(), "blocked"); err != nil {
		t.Fatal(err)
	}
	res = s.call(t, s.seal20(t, p, "chain", "request_contact", map[string]any{"card": card20(p)}, func(o *pactidentity.SealOpts) { o.MsgID = "blocked" }))
	if opened := s.openResult(t, res, p, "blocked"); !strings.Contains(string(opened.Result), "pending") {
		t.Fatalf("a blocked contact must get a stranger's answer: %s", opened.Result)
	}
	if rows, _ := s.st.ListContacts(ctx, s.acct.ID); len(rows) != 1 || rows[0].Status != "blocked" {
		t.Fatalf("blocking must stay silent: %+v", rows)
	}
}

func TestSealed20NewAddressUnderAskAnswersPending(t *testing.T) {
	s := newSealed20Env(t)
	ctx := context.Background()
	p := newPeer(t, fixedNow)
	s.pin(t, p, "active")
	if err := s.st.SetAccountHostPolicy(ctx, s.acct.ID, "ask", true); err != nil {
		t.Fatal(err)
	}
	moved := &peer{root: p.root, host: p.host}
	moved.leaf = moved.leafFor(t, endpointA2, fixedNow.Add(-15*time.Minute))
	opened := s.openResult(t, s.call(t, s.seal20(t, moved, "chain", "update_contact", map[string]any{"card": card20(moved)}, func(o *pactidentity.SealOpts) { o.MsgID = "move" })), p, "move")
	if string(opened.Result) != `{"status":"pending"}` {
		t.Fatalf("a move under ask: %s", opened.Result)
	}
	// Every other call from the new address waits too: the seed answers each
	// one pending until the owner decides, and nothing runs.
	opened = s.openResult(t, s.call(t, s.seal20(t, moved, "chain", "send_message", map[string]any{"text": "hi"}, func(o *pactidentity.SealOpts) { o.MsgID = "move2" })), p, "move2")
	if string(opened.Result) != `{"status":"pending"}` {
		t.Fatalf("a call from an unapproved address: %s", opened.Result)
	}
	if c, _ := s.st.GetContact(ctx, s.acct.ID, p.fpr()); c.Endpoint != endpointA {
		t.Fatalf("the pin must not move until the owner answers: %+v", c)
	}
	// A pinned root that is still waiting for OUR approval of its request
	// (pending_out) may answer it and nothing else.
	waiting := newPeer(t, fixedNow)
	s.pin(t, waiting, "pending_out")
	res := s.call(t, s.seal20(t, waiting, "chain", "send_message", map[string]any{"text": "hi"}, func(o *pactidentity.SealOpts) { o.MsgID = "early" }))
	if !res.IsError || text(res) != `{"code":"pending_approval"}` {
		t.Fatalf("a pending_out root calling ahead of its answer: %s", text(res))
	}
	var _ store.Contact
}

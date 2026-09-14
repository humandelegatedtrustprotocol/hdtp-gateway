package public

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// sealedEnv wires a registry with one tool per tier plus sealed_call, a pool,
// and the identifier — the shape serve composes.
type sealedEnv struct {
	*idEnv
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

func newSealedEnv(t *testing.T) *sealedEnv {
	t.Helper()
	e := newIdEnv(t, identity.AlgoP256)
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
		Pool: pool, Identifier: e.id, AccountID: e.acct.ID, AccountFpr: e.acctKP.Fingerprint,
		Keypair: func(context.Context) (*identity.Keypair, error) { return e.acctKP, nil },
		Idem:    e.st, Now: func() time.Time { return fixedNow },
	}
	reg.Add(SealedEntries(deps)...)
	return &sealedEnv{idEnv: e, pool: pool, deps: deps}
}

// call invokes sealed_call the way an MCP server would.
func (s *sealedEnv) call(t *testing.T, env *envelope.Envelope, tf TransportFacts) *mcp.CallToolResult {
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
		t.Fatalf("handler error: %v", err)
	}
	return res
}

// openResult unseals the returned envelope with the caller's key.
func (s *sealedEnv) openResult(t *testing.T, res *mcp.CallToolResult, caller *identity.Keypair) []byte {
	t.Helper()
	if res.IsError {
		t.Fatalf("wrapper error: %s", res.Content[0].(*mcp.TextContent).Text)
	}
	var out envelope.Envelope
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out); err != nil {
		t.Fatal(err)
	}
	h, err := envelope.ParseHeader(&out)
	if err != nil {
		t.Fatal(err)
	}
	if h.To != caller.Fingerprint || h.From != s.acctKP.Fingerprint || h.CTY != "application/pact-result+json" {
		t.Fatalf("result header not swapped/typed: %+v", h)
	}
	if err := envelope.VerifySig(&out, s.acctKP.Signer.Public()); err != nil {
		t.Fatalf("result signature: %v", err)
	}
	plain, err := envelope.Open(caller, &out)
	if err != nil {
		t.Fatalf("open result: %v", err)
	}
	return plain
}

// AC: sealed tools/list equals plaintext tools/list for the same caller.
func TestSealedToolsListEqualsPlaintextForSameCaller(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	c := s.sender(t, "contact", identity.AlgoP256)
	if _, err := s.st.InsertContact(ctx, store.Contact{
		AccountID: s.acct.ID, Fingerprint: c.Fingerprint, SPKI: spkiOf(t, c),
		Status: "active", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}
	// plaintext: the composed server's own tool list
	srv, err := s.pool.ServerFor(ctx, s.acct.ID, c.Fingerprint)
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
	defer cs.Close()
	plainList, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	plainNames := map[string]bool{}
	for _, tl := range plainList.Tools {
		plainNames[tl.Name] = true
	}

	// sealed: the same list, through the envelope
	env := s.seal(t, c, payload(t, "tools/list", "", "", ""))
	plain := s.openResult(t, s.call(t, env, TransportFacts{}), c)
	var sealedList struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(plain, &sealedList); err != nil {
		t.Fatalf("result payload: %s", plain)
	}
	sealedNames := map[string]bool{}
	for _, tl := range sealedList.Tools {
		sealedNames[tl.Name] = true
	}
	if len(sealedNames) != len(plainNames) {
		t.Fatalf("sealed %v != plaintext %v", sealedNames, plainNames)
	}
	for n := range plainNames {
		if !sealedNames[n] {
			t.Fatalf("sealed list missing %s (plaintext %v, sealed %v)", n, plainNames, sealedNames)
		}
	}
	// and the contact's surface is the permission-filtered one
	if !sealedNames["send_message"] || sealedNames["book_slot"] || !sealedNames[SealedToolName] {
		t.Fatalf("surface wrong: %v", sealedNames)
	}
}

// AC: a sealed call by an unknown-key guest reaches guest tools only.
func TestSealedGuestReachesGuestToolsOnly(t *testing.T) {
	s := newSealedEnv(t)
	g := s.sender(t, "guest", identity.AlgoEd25519)
	spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, g))

	// the guest tool it is entitled to
	env := s.seal(t, g, payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk), msgID("g-1"))
	plain := s.openResult(t, s.call(t, env, TransportFacts{}), g)
	if !strings.Contains(string(plain), "ran:redeem_invite") {
		t.Fatalf("guest tool did not run: %s", plain)
	}
	// a contact-tier tool: `blocked_or_unknown`, the guest-tier catch-all PACT
	// §12 mandates — the same answer a blocked caller gets, and indistinguishable
	// from a tool that does not exist.
	env = s.seal(t, g, payload(t, "tools/call", "send_message", cardFor(g.Fingerprint), spk), msgID("g-2"))
	plain = s.openResult(t, s.call(t, env, TransportFacts{}), g)
	if !strings.Contains(string(plain), "blocked_or_unknown") || strings.Contains(string(plain), "ran:") {
		t.Fatalf("guest reached a contact tool: %s", plain)
	}
	// a tool that does not exist at all looks exactly the same
	env = s.seal(t, g, payload(t, "tools/call", "no_such_tool", cardFor(g.Fingerprint), spk), msgID("g-3"))
	plain2 := s.openResult(t, s.call(t, env, TransportFacts{}), g)
	if string(plain2) != string(plain) {
		t.Fatalf("absent vs forbidden distinguishable:\n%s\n%s", plain, plain2)
	}
}

// AC: a plaintext substantive call to a seal=required account → seal_required.
func TestPlaintextToSealRequiredAccountRefused(t *testing.T) {
	s := newSealedEnv(t)
	tf := TransportFacts{ClientCertFingerprint: "sha256:caller"}
	if _, err := s.id.PlaintextGateCtx(context.Background(), tf, "send_message", true); Code(err) != "seal_required" {
		t.Fatalf("substantive plaintext: %v", Code(err))
	}
	// tools/list still answers, and sealed_call itself is never "substantive"
	if _, err := s.id.PlaintextGateCtx(context.Background(), tf, "tools/list", false); err != nil {
		t.Fatalf("tools/list refused: %v", err)
	}
	if _, err := s.id.PlaintextGateCtx(context.Background(), tf, SealedToolName, false); err != nil {
		t.Fatalf("sealed_call refused: %v", err)
	}
	// with seal optional the same call goes through
	s.id.Seal = core.SealOptional
	if _, err := s.id.PlaintextGateCtx(context.Background(), tf, "send_message", true); err != nil {
		t.Fatalf("optional seal refused a plaintext call: %v", err)
	}
}

func TestSealedCallIsPresentAtEveryTier(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	guest := s.sender(t, "guest", identity.AlgoP256)
	pending := s.sender(t, "pending", identity.AlgoP256)
	contact := s.sender(t, "contact", identity.AlgoP256)
	_, _ = s.st.InsertContact(ctx, store.Contact{AccountID: s.acct.ID, Fingerprint: pending.Fingerprint, SPKI: spkiOf(t, pending), Status: "pending_in"})
	_, _ = s.st.InsertContact(ctx, store.Contact{AccountID: s.acct.ID, Fingerprint: contact.Fingerprint, SPKI: spkiOf(t, contact), Status: "active"})

	for _, kp := range []*identity.Keypair{guest, pending, contact} {
		srv, err := s.pool.ServerFor(ctx, s.acct.ID, kp.Fingerprint)
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
			t.Fatalf("%s sees sealed_call %d times, want exactly 1", kp.Fingerprint, seen)
		}
	}
}

// A replayed msg_id returns the recorded acknowledgment without re-running the
// inner tool (§4.4 step 8) — and the answer is still sealed.
func TestSealedReplayReturnsRecordedResult(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	c := s.sender(t, "contact", identity.AlgoP256)
	_, _ = s.st.InsertContact(ctx, store.Contact{
		AccountID: s.acct.ID, Fingerprint: c.Fingerprint, SPKI: spkiOf(t, c),
		Status: "active", Permissions: []string{"message.text"},
	})
	env := s.seal(t, c, payload(t, "tools/call", "send_message", "", ""))
	first := s.openResult(t, s.call(t, env, TransportFacts{}), c)
	if !strings.Contains(string(first), "ran:send_message") {
		t.Fatalf("first call: %s", first)
	}
	// The envelope's record lives in its own namespace (§4.5): the envelope's
	// msg_id deduplicates the ENVELOPE, and an inner tool that takes a msg_id of
	// its own keeps its own idempotency. They shared one key until now, so a
	// sealed book_slot reserved the id as an envelope and then read its own
	// reservation as another attempt in flight — every sealed booking failed.
	stored, _, err := s.st.PutIdempotency(ctx, s.acct.ID, c.Fingerprint, EnvelopeKey("m1"), "", 0)
	if err != nil || stored == "" {
		t.Fatalf("ack not recorded under the envelope key: %q %v", stored, err)
	}
	free, existed, err := s.st.PutIdempotency(ctx, s.acct.ID, c.Fingerprint, "m1", "", 0)
	if err != nil || existed || free != "" {
		t.Fatalf("the envelope claimed the id an inner tool needs: existed=%v ack=%q %v", existed, free, err)
	}
	second := s.openResult(t, s.call(t, env, TransportFacts{}), c)
	if string(second) != string(first) {
		t.Fatalf("replay differs:\n%s\n%s", first, second)
	}
}

// PACT §12: one call, one budget unit. The outer sealed_call wrapper used to
// spend a unit BEFORE the envelope was opened — classified from transport
// facts, which behind a terminating edge is an anonymous guest — and the inner
// dispatch then spent the contact's unit too: every sealed contact was double
// billed, and edge-mode contacts burned the shared per-IP guest budget
// (10/hour) on the wrapper. The wrapper is exempt now; the one unit is the
// inner, envelope-classified consumption.
func TestASealedCallSpendsExactlyOneBudgetUnit(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	c := s.sender(t, "carol", identity.AlgoP256)
	if _, err := s.st.InsertContact(ctx, store.Contact{
		AccountID: s.acct.ID, Fingerprint: c.Fingerprint, SPKI: spkiOf(t, c),
		Status: "active", Permissions: []string{"message.text"},
	}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var sawEnvelope []bool // one element per consumption
	s.pool.Limit = func(ctx context.Context) (bool, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		sawEnvelope = append(sawEnvelope, EnvelopeFactsFrom(ctx) != nil)
		return true, 0
	}

	// The sealed entry, invoked through guarded() — the exact outer path the
	// composed MCP server serves.
	// A certificate-less edge caller resolves as a transport GUEST, so the
	// guest-tier sealed entry is the one its composed server carries — the
	// envelope elevates the identity inside.
	var sealed *Entry
	for _, e := range s.pool.Registry.snapshot() {
		if e.Tool.Name == SealedToolName && e.Rule.Tier == policy.TierGuest {
			ee := e
			sealed = &ee
			break
		}
	}
	if sealed == nil {
		t.Fatal("no guest-tier sealed entry registered")
	}
	env := s.seal(t, c, payload(t, "tools/call", "send_message", "", ""), msgID("bd-1"))
	args, _ := json.Marshal(env)
	tctx := context.WithValue(ctx, factsKey{}, TransportFacts{}) // edge: no cert
	res, err := s.pool.guarded(s.acct.ID, "", *sealed)(tctx, &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: SealedToolName, Arguments: args},
	})
	if err != nil || res.IsError {
		t.Fatalf("sealed call failed: %v %v", err, res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sawEnvelope) != 1 || !sawEnvelope[0] {
		t.Fatalf("budget consumptions = %v, want exactly one WITH envelope facts", sawEnvelope)
	}
}

// And the exemption is scoped: a plain tool through the same wrapper still
// spends its unit at the outer gate, classified from transport facts.
func TestAPlainCallStillSpendsItsUnitAtTheOuterGate(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	var mu sync.Mutex
	var sawEnvelope []bool
	s.pool.Limit = func(ctx context.Context) (bool, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		sawEnvelope = append(sawEnvelope, EnvelopeFactsFrom(ctx) != nil)
		return true, 0
	}
	var entry *Entry
	for _, e := range s.pool.Registry.snapshot() {
		if e.Tool.Name == "redeem_invite" {
			ee := e
			entry = &ee
			break
		}
	}
	tctx := context.WithValue(ctx, factsKey{}, TransportFacts{})
	if _, err := s.pool.guarded(s.acct.ID, "", *entry)(tctx, &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "redeem_invite", Arguments: json.RawMessage(`{}`)},
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sawEnvelope) != 1 || sawEnvelope[0] {
		t.Fatalf("budget consumptions = %v, want exactly one WITHOUT envelope facts", sawEnvelope)
	}
}

// PACT §13.4: at `none` the recipient does not accept envelopes. And §13.1:
// msg_id is REQUIRED and non-empty — a replay guard keyed on "" guards nothing.
func TestSealNoneRefusesEnvelopesAndEmptyMsgIDIsInvalid(t *testing.T) {
	e := newIdEnv(t, identity.AlgoP256)
	g := e.sender(t, "guest", identity.AlgoEd25519)
	spk := base64.RawURLEncoding.EncodeToString(spkiOf(t, g))

	e.id.Seal = core.SealNone
	env := e.seal(t, g, payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk))
	if _, err := e.open(t, env, TransportFacts{}, DeliveryDirect); Code(err) != "seal_not_accepted" {
		t.Fatalf("seal:none accepted an envelope: %v", err)
	}

	e.id.Seal = core.SealOptional
	env = e.seal(t, g, payload(t, "tools/call", "redeem_invite", cardFor(g.Fingerprint), spk), msgID(""))
	if _, err := e.open(t, env, TransportFacts{}, DeliveryDirect); Code(err) != "envelope_invalid" {
		t.Fatalf("an empty msg_id was accepted: %v", err)
	}
}

// PACT §13.2: once the envelope opened, even an ERROR result is sealed back —
// a plaintext error is only for an envelope that could not be opened at all.
func TestDispatchErrorsAreSealedBack(t *testing.T) {
	s := newSealedEnv(t)
	ctx := context.Background()
	c := s.sender(t, "contact", identity.AlgoP256)
	_, _ = s.st.InsertContact(ctx, store.Contact{
		AccountID: s.acct.ID, Fingerprint: c.Fingerprint, SPKI: spkiOf(t, c),
		Status: "active", Permissions: []string{"message.text"},
	})
	// A pinned contact, so the envelope opens — and inner params that do not
	// parse, so Dispatch itself errors after the open.
	raw := []byte(`{"method":"tools/call","params":"not-an-object"}`)
	env := s.seal(t, c, raw, msgID("e-1"))
	res := s.call(t, env, TransportFacts{})
	if res.IsError {
		t.Fatalf("post-open failure answered as a plaintext error: %s",
			res.Content[0].(*mcp.TextContent).Text)
	}
	plain := s.openResult(t, res, c)
	if !strings.Contains(string(plain), "unavailable") {
		t.Fatalf("sealed error result: %s", plain)
	}
}

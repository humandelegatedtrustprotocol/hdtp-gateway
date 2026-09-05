package relay

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

type relayEnv struct {
	srv   *Server
	st    store.Store
	rows  []string
	mu    sync.Mutex
	pings []string
	clock time.Time
}

func newRelay(t *testing.T) *relayEnv {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &relayEnv{st: st, clock: time.Unix(1756000000, 0)}
	e.srv = &Server{
		Store: st, Now: func() time.Time { return e.clock },
		Audit:  func(a, r, o string) { e.mu.Lock(); e.rows = append(e.rows, a+" "+r+" "+o); e.mu.Unlock() },
		Notify: func(fpr string) { e.mu.Lock(); e.pings = append(e.pings, fpr); e.mu.Unlock() },
	}
	return e
}

func (e *relayEnv) has(sub string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rows {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// as makes the relay see a given caller certificate for one call.
func (e *relayEnv) as(kp *identity.Keypair) {
	spki, _ := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	e.srv.Caller = func(context.Context) ([]byte, string, bool) { return spki, kp.Fingerprint, true }
}

func (e *relayEnv) call(t *testing.T, tool string, args any) *mcp.CallToolResult {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	var h mcp.ToolHandler
	switch tool {
	case "relay_call":
		h = e.srv.relayCall
	case "fetch_queued":
		h = e.srv.fetchQueued
	case "ack":
		h = e.srv.ack
	default:
		t.Fatalf("unknown tool %s", tool)
	}
	res, err := h(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: b}})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

// sync drives the allow-list control endpoint the way the wire would: a POST
// under the caller identity e.as() last installed.
func (e *relayEnv) sync(t *testing.T, senders []string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(map[string]any{"senders": senders})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	e.srv.AllowlistHandler().ServeHTTP(w, httptest.NewRequest("POST", "/relay/allowlist", bytes.NewReader(b)))
	return w
}

func text(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	tc, _ := res.Content[0].(*mcp.TextContent)
	if tc == nil {
		return ""
	}
	return tc.Text
}

func sealTo(t *testing.T, sender, recipient *identity.Keypair, clock time.Time, msgID string, lifetime time.Duration) *envelope.Envelope {
	t.Helper()
	env, err := envelope.Seal(envelope.SealParams{
		Sender: sender, RecipientPub: recipient.Signer.Public(), To: recipient.Fingerprint,
		MsgID: msgID, TS: clock.Unix(), Exp: clock.Add(lifetime).Unix(), CTY: "application/pact-call+json",
	}, []byte(`{"method":"tools/call","params":{"name":"send_message","arguments":{"text":"hi"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// AC: a disallowed sender is rejected; an allow-listed one is queued, fetched,
// acked and deleted.
func TestRelayAllowlistQueueFetchAck(t *testing.T) {
	e := newRelay(t)
	ctx := context.Background()
	alice, _ := identity.Generate(identity.AlgoP256)   // sender
	bob, _ := identity.Generate(identity.AlgoP256)     // recipient
	mallory, _ := identity.Generate(identity.AlgoP256) // not on the list

	// Bob syncs his allow-list (his active contacts)
	e.as(bob)
	if w := e.sync(t, []string{alice.Fingerprint}); w.Code != 200 {
		t.Fatalf("sync: %d %s", w.Code, w.Body.String())
	}

	// Mallory is refused — and the refusal is audited
	e.as(mallory)
	res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, mallory, bob, e.clock, "m-1", time.Hour)})
	if !res.IsError || !strings.Contains(text(res), "permission_denied") {
		t.Fatalf("disallowed sender queued: %s", text(res))
	}
	if !e.has("relay_call sender:" + mallory.Fingerprint + "->" + bob.Fingerprint + " permission_denied") {
		t.Fatalf("refusal not audited: %v", e.rows)
	}
	if n, _ := e.st.CountRelayQueue(ctx, bob.Fingerprint, e.clock.Unix()); n != 0 {
		t.Fatalf("queue should be empty: %d", n)
	}

	// Alice is allowed: queued, and Bob gets a content-free ping
	e.as(alice)
	env := sealTo(t, alice, bob, e.clock, "a-1", time.Hour)
	res = e.call(t, "relay_call", map[string]any{"envelope": env})
	if res.IsError {
		t.Fatalf("allowed sender refused: %s", text(res))
	}
	e.mu.Lock()
	pinged := len(e.pings) == 1 && e.pings[0] == bob.Fingerprint
	e.mu.Unlock()
	if !pinged {
		t.Fatalf("no you-have-mail ping: %v", e.pings)
	}

	// Bob fetches his own queue and gets the envelope VERBATIM
	e.as(bob)
	res = e.call(t, "fetch_queued", map[string]any{})
	var fetched struct {
		Items []struct {
			ID       string             `json:"id"`
			Envelope *envelope.Envelope `json:"envelope"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(text(res)), &fetched); err != nil {
		t.Fatalf("fetch: %s", text(res))
	}
	if len(fetched.Items) != 1 {
		t.Fatalf("fetched %d items", len(fetched.Items))
	}
	got := fetched.Items[0].Envelope
	if string(got.CT) != string(env.CT) || string(got.Sig) != string(env.Sig) {
		t.Fatal("envelope was not relayed verbatim")
	}
	// and only Bob can open it — the relay never could
	plain, err := envelope.Open(bob, got)
	if err != nil || !strings.Contains(string(plain), "send_message") {
		t.Fatalf("recipient could not open: %v", err)
	}

	// ack deletes it
	if res := e.call(t, "ack", map[string]any{"id": fetched.Items[0].ID}); res.IsError || !strings.Contains(text(res), `"deleted":true`) {
		t.Fatalf("ack: %s", text(res))
	}
	if n, _ := e.st.CountRelayQueue(ctx, bob.Fingerprint, e.clock.Unix()); n != 0 {
		t.Fatalf("acked item still queued: %d", n)
	}
	// a stranger cannot ack someone else's item
	e.as(alice)
	if res := e.call(t, "ack", map[string]any{"id": "whatever"}); strings.Contains(text(res), `"deleted":true`) {
		t.Fatal("cross-node ack succeeded")
	}
}

func TestRelayRejectsForgedAndMisroutedEnvelopes(t *testing.T) {
	e := newRelay(t)
	alice, _ := identity.Generate(identity.AlgoP256)
	bob, _ := identity.Generate(identity.AlgoP256)
	e.as(bob)
	e.sync(t, []string{alice.Fingerprint})

	// Alice's certificate, but an envelope claiming to be from someone else
	other, _ := identity.Generate(identity.AlgoP256)
	e.as(alice)
	if res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, other, bob, e.clock, "x", time.Hour)}); !res.IsError {
		t.Fatal("envelope signed by a different key accepted")
	}
	// no certificate at all: identity_required (a relay cannot run behind an edge)
	e.srv.Caller = func(context.Context) ([]byte, string, bool) { return nil, "", false }
	if res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "y", time.Hour)}); !strings.Contains(text(res), "identity_required") {
		t.Fatalf("certificate-less relay_call: %s", text(res))
	}
	// `to` argument disagreeing with the envelope's own routing
	e.as(alice)
	if res := e.call(t, "relay_call", map[string]any{"to": "sha256:elsewhere", "envelope": sealTo(t, alice, bob, e.clock, "z", time.Hour)}); !res.IsError {
		t.Fatal("misrouted envelope accepted")
	}
}

// AC: retention is min(envelope exp, 30 days) and expired entries are purged.
func TestRelayRetentionAndPurge(t *testing.T) {
	e := newRelay(t)
	ctx := context.Background()
	alice, _ := identity.Generate(identity.AlgoP256)
	bob, _ := identity.Generate(identity.AlgoP256)
	e.as(bob)
	e.sync(t, []string{alice.Fingerprint})
	e.as(alice)

	// an envelope asking for 25 days keeps its own exp
	short := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "short", 25*24*time.Hour)})
	var shortRes struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	_ = json.Unmarshal([]byte(text(short)), &shortRes)
	if want := e.clock.Add(25 * 24 * time.Hour).Unix(); shortRes.ExpiresAt != want {
		t.Fatalf("exp %d, want %d", shortRes.ExpiresAt, want)
	}
	// one queued for 2 hours expires and is purged on the next fetch
	if res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "brief", 2*time.Hour)}); res.IsError {
		t.Fatalf("queue: %s", text(res))
	}
	if n, _ := e.st.CountRelayQueue(ctx, bob.Fingerprint, e.clock.Unix()); n != 2 {
		t.Fatalf("queued %d", n)
	}
	e.clock = e.clock.Add(3 * time.Hour)
	e.as(bob)
	res := e.call(t, "fetch_queued", map[string]any{})
	var fetched struct {
		Items []struct{ ID string } `json:"items"`
	}
	_ = json.Unmarshal([]byte(text(res)), &fetched)
	if len(fetched.Items) != 1 {
		t.Fatalf("expired item still delivered: %d", len(fetched.Items))
	}
	if n, _ := e.st.CountRelayQueue(ctx, bob.Fingerprint, e.clock.Unix()); n != 1 {
		t.Fatalf("purge left %d", n)
	}
}

// AC (type-level): the relay path never opens an envelope. Assert it
// structurally — server.go must not reference envelope.Open at all.
func TestRelayNeverOpensEnvelopes(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "envelope" {
			return true
		}
		switch sel.Sel.Name {
		case "Open", "Seal", "SealSeeded":
			t.Fatalf("the relay path calls envelope.%s — a relay must never hold plaintext", sel.Sel.Name)
		}
		return true
	})
	// and it must not reach for account keys either
	src, err := readFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"GetAccountSealedKey", "LoadKeypair", "identity.Manager"} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("relay server references %s", forbidden)
		}
	}
}

func readFile(name string) (string, error) {
	data, err := os.ReadFile(name)
	return string(data), err
}

// AC (P10-13): the relay's MCP surface is EXACTLY the three verbs PACT §9
// defines. A fourth tool there would have every peer's `tools/list` advertise
// something the protocol does not describe, and a peer cannot tell a local
// extension from a verb it should have implemented.
func TestRelayMCPSurfaceIsExactlyPACTsThreeVerbs(t *testing.T) {
	e := newRelay(t)
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := e.srv.MCPServer().Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Wait()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range list.Tools {
		got[tool.Name] = true
	}
	want := []string{"relay_call", "fetch_queued", "ack"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("PACT §9 verb %q is missing from the relay surface", w)
		}
		delete(got, w)
	}
	for extra := range got {
		t.Errorf("relay advertises %q, which PACT §9 does not define", extra)
	}
	// The handler seam must agree with the surface, or an in-process caller
	// could still reach what the wire no longer offers.
	if res, _ := e.srv.Handler("sync_allowlist")(ctx,
		&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "sync_allowlist"}}); !res.IsError {
		t.Error("Handler still resolves sync_allowlist")
	}
}

// AC (P10-13): the control endpoint needs a client certificate, and the caller
// can only ever set its OWN list — the recipient comes from the certificate,
// never from the body.
func TestAllowlistControlEndpointIsBoundToTheCallersCertificate(t *testing.T) {
	e := newRelay(t)
	ctx := context.Background()
	bob, _ := identity.Generate(identity.AlgoP256)
	mallory, _ := identity.Generate(identity.AlgoP256)
	alice, _ := identity.Generate(identity.AlgoP256)

	// No certificate: no identity to attribute a list to.
	e.srv.Caller = func(context.Context) ([]byte, string, bool) { return nil, "", false }
	if w := e.sync(t, []string{alice.Fingerprint}); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "identity_required") {
		t.Fatalf("anonymous sync accepted: %d %s", w.Code, w.Body.String())
	}
	if !e.has("relay_allowlist recipient:unknown identity_required") {
		t.Errorf("anonymous refusal not audited: %v", e.rows)
	}

	// Mallory can write only Mallory's list, however the body is shaped.
	e.as(mallory)
	if w := e.sync(t, []string{alice.Fingerprint}); w.Code != 200 {
		t.Fatalf("mallory sync: %d", w.Code)
	}
	ok, err := e.st.RelayAllowed(ctx, bob.Fingerprint, alice.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("one caller's sync wrote another node's allow-list")
	}

	// Garbage entries are refused rather than stored.
	e.as(bob)
	if w := e.sync(t, []string{"not-a-fingerprint"}); w.Code != 400 {
		t.Fatalf("malformed fingerprint accepted: %d", w.Code)
	}
	// ...and a GET is not a way in either.
	w := httptest.NewRecorder()
	e.srv.AllowlistHandler().ServeHTTP(w, httptest.NewRequest("GET", "/relay/allowlist", nil))
	if w.Code != 405 {
		t.Fatalf("GET accepted: %d", w.Code)
	}
}

// AC (P12-15): a relay serves the recipients its operator chose, not everyone.
//
// relay_call already refuses a sender who is not on the recipient's allow-list,
// so mail could not be queued for a stranger. But nothing gated becoming a
// recipient: any caller presenting any client certificate could POST an
// allow-list and be stored as one, and certificates are free to mint. An
// operator who turned on `relay: true` for their own household was running a
// public store-and-forward service — storage growth at a stranger's discretion,
// with the stranger's own chosen senders then permitted to queue.
func TestRelayOnlyRegistersRecipientsItServes(t *testing.T) {
	e := newRelay(t)
	sender, _ := identity.Generate(identity.AlgoP256)
	served, _ := identity.Generate(identity.AlgoP256)
	stranger, _ := identity.Generate(identity.AlgoP256)

	e.srv.Serves = func(fpr string) bool { return fpr == served.Fingerprint }

	e.as(served)
	if w := e.sync(t, []string{sender.Fingerprint}); w.Code != 200 {
		t.Fatalf("a recipient this relay serves was refused: %d %s", w.Code, w.Body.String())
	}

	e.as(stranger)
	w := e.sync(t, []string{sender.Fingerprint})
	if w.Code == 200 {
		t.Fatal("a stranger registered itself as a recipient on a relay that does not serve it")
	}
	if !strings.Contains(w.Body.String(), "permission_denied") {
		t.Fatalf("refusal was not permission_denied: %s", w.Body.String())
	}
	ok, err := e.st.RelayAllowed(context.Background(), stranger.Fingerprint, sender.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the refused registration was written anyway")
	}

	// Serves nil is an OPEN relay — the documented default, kept so turning the
	// knob on is what changes behaviour, never an upgrade.
	e.srv.Serves = nil
	e.as(stranger)
	if w := e.sync(t, []string{sender.Fingerprint}); w.Code != 200 {
		t.Fatalf("an open relay refused a registration: %d", w.Code)
	}
}

// AC (P13-01): turning on relay_recipients must stop serving strangers who
// registered while the relay was open — not merely stop NEW registrations.
//
// P12-15 gated the allow-list endpoint, which is where a node becomes a
// recipient. It did not gate relay_call, which reads only the recipient's stored
// allow-list. So every registration made before the operator set the knob kept
// working: the operator turns on "serve only my nodes", sees registrations
// refused, and keeps carrying mail for everyone who got in first. Enforcing at
// USE is also what makes the knob safe to narrow later, without a purge that
// could not be undone.
func TestNarrowingTheRecipientListStopsServingEarlierRegistrations(t *testing.T) {
	e := newRelay(t)
	ctx := context.Background()
	sender, _ := identity.Generate(identity.AlgoP256)
	squatter, _ := identity.Generate(identity.AlgoP256)
	served, _ := identity.Generate(identity.AlgoP256)

	// While the relay is OPEN, both register.
	for _, kp := range []*identity.Keypair{squatter, served} {
		e.as(kp)
		if w := e.sync(t, []string{sender.Fingerprint}); w.Code != 200 {
			t.Fatalf("open relay refused a registration: %d", w.Code)
		}
	}

	// The operator now serves only their own node.
	e.srv.Serves = func(fpr string) bool { return fpr == served.Fingerprint }

	e.as(sender)
	res := e.call(t, "relay_call", map[string]any{
		"envelope": sealTo(t, sender, squatter, e.clock, "sq-1", time.Hour)})
	if !res.IsError || !strings.Contains(text(res), "permission_denied") {
		t.Fatalf("the relay still queued for a recipient it no longer serves: %s", text(res))
	}
	if n, _ := e.st.CountRelayQueue(ctx, squatter.Fingerprint, e.clock.Unix()); n != 0 {
		t.Fatalf("%d items queued for an unserved recipient", n)
	}

	// The served recipient is unaffected.
	res = e.call(t, "relay_call", map[string]any{
		"envelope": sealTo(t, sender, served, e.clock, "sv-1", time.Hour)})
	if res.IsError {
		t.Fatalf("a served recipient was refused: %s", text(res))
	}
}

// PACT §9: a relay SHOULD bound per-recipient queue depth and MAY refuse
// relay_call with rate_limited when a queue is full. Without a bound, one
// allow-listed sender could hold a recipient's relay hostage byte by byte.
func TestRelayRefusesAFullQueue(t *testing.T) {
	e := newRelay(t)
	ctx := context.Background()
	alice, _ := identity.Generate(identity.AlgoP256)
	bob, _ := identity.Generate(identity.AlgoP256)
	e.srv.MaxQueue = 2

	e.as(bob)
	if w := e.sync(t, []string{alice.Fingerprint}); w.Code != 200 {
		t.Fatalf("sync: %d", w.Code)
	}
	e.as(alice)
	for i, id := range []string{"q-1", "q-2"} {
		if res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, id, time.Hour)}); res.IsError {
			t.Fatalf("item %d refused inside the quota: %s", i+1, text(res))
		}
	}
	res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "q-3", time.Hour)})
	if !res.IsError || !strings.Contains(text(res), "rate_limited") {
		t.Fatalf("a full queue accepted more: %s", text(res))
	}
	if !e.has("relay_call sender:" + alice.Fingerprint + "->" + bob.Fingerprint + " rate_limited") {
		t.Fatalf("the refusal was not audited: %v", e.rows)
	}
	// Draining makes room: ack one, the next call is accepted.
	e.as(bob)
	items, err := e.st.FetchRelayQueue(ctx, bob.Fingerprint, e.clock.Unix(), 1)
	if err != nil || len(items) != 1 {
		t.Fatalf("fetch: %v %d", err, len(items))
	}
	if res := e.call(t, "ack", map[string]any{"id": items[0].ID}); res.IsError {
		t.Fatalf("ack: %s", text(res))
	}
	e.as(alice)
	if res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "q-4", time.Hour)}); res.IsError {
		t.Fatalf("room was made but the call was refused: %s", text(res))
	}
}

// The byte dimension holds too: envelopes are large, so a count alone would
// still allow a huge queue.
func TestRelayRefusesAQueueOverItsByteBudget(t *testing.T) {
	e := newRelay(t)
	alice, _ := identity.Generate(identity.AlgoP256)
	bob, _ := identity.Generate(identity.AlgoP256)

	e.as(bob)
	if w := e.sync(t, []string{alice.Fingerprint}); w.Code != 200 {
		t.Fatalf("sync: %d", w.Code)
	}
	e.as(alice)
	one := sealTo(t, alice, bob, e.clock, "b-1", time.Hour)
	oneBytes, _ := json.Marshal(one)
	// Budget fits exactly one queued envelope; the second must trip the bytes
	// check even though the item count (MaxQueue default 100) never would.
	e.srv.MaxQueueBytes = int64(len(oneBytes)) + 8
	if res := e.call(t, "relay_call", map[string]any{"envelope": one}); res.IsError {
		t.Fatalf("first item refused: %s", text(res))
	}
	res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "b-2", time.Hour)})
	if !res.IsError || !strings.Contains(text(res), "rate_limited") {
		t.Fatalf("the byte budget did not hold: %s", text(res))
	}
}

// PACT §9's "you have mail" without inventing a channel: fetch_queued with
// wait_seconds holds an empty fetch until a relay_call for that recipient
// arrives (or the bounded wait ends). The recipient's own open call is the
// only wire a relay-assisted node has for a wake.
func TestFetchQueuedLongPollReleasesOnRelayCall(t *testing.T) {
	e := newRelay(t)
	alice, _ := identity.Generate(identity.AlgoP256)
	bob, _ := identity.Generate(identity.AlgoP256)
	e.as(bob)
	if w := e.sync(t, []string{alice.Fingerprint}); w.Code != 200 {
		t.Fatalf("sync: %d", w.Code)
	}

	type fetchOut struct {
		res     *mcp.CallToolResult
		elapsed time.Duration
	}
	done := make(chan fetchOut, 1)
	go func() {
		start := time.Now()
		res := e.call(t, "fetch_queued", map[string]any{"wait_seconds": 10})
		done <- fetchOut{res, time.Since(start)}
	}()

	// The hold is in place before the wake fires — poll the registry rather
	// than sleeping and hoping.
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.srv.waitMu.Lock()
		n := len(e.srv.waiters[bob.Fingerprint])
		e.srv.waitMu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fetch never registered a hold")
		}
		time.Sleep(5 * time.Millisecond)
	}

	e.as(alice)
	if res := e.call(t, "relay_call", map[string]any{"envelope": sealTo(t, alice, bob, e.clock, "lp-1", time.Hour)}); res.IsError {
		t.Fatalf("relay_call: %s", text(res))
	}
	out := <-done
	if out.elapsed >= 5*time.Second {
		t.Fatalf("the hold was not released by the relay_call (took %v)", out.elapsed)
	}
	if !strings.Contains(text(out.res), "lp-1") && !strings.Contains(text(out.res), "envelope") {
		t.Fatalf("the released fetch returned nothing: %s", text(out.res))
	}
	e.srv.waitMu.Lock()
	left := len(e.srv.waiters)
	e.srv.waitMu.Unlock()
	if left != 0 {
		t.Fatalf("waiter registry leaked: %d entries", left)
	}
}

// An empty hold ends at the bounded wait and answers empty — and wait_seconds
// beyond MaxWait is clamped, because the outbound client's whole call budget
// is 30 seconds.
func TestFetchQueuedLongPollTimesOutEmpty(t *testing.T) {
	e := newRelay(t)
	bob, _ := identity.Generate(identity.AlgoP256)
	e.as(bob)
	start := time.Now()
	res := e.call(t, "fetch_queued", map[string]any{"wait_seconds": 1})
	if got := time.Since(start); got < 900*time.Millisecond || got > 5*time.Second {
		t.Fatalf("hold length: %v", got)
	}
	if !strings.Contains(text(res), `"items":[]`) {
		t.Fatalf("timed-out hold: %s", text(res))
	}
}

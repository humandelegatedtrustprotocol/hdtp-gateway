package relay

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/envelope"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/public"
)

// inProcess speaks to a relay Server as a given node (its client certificate).
type inProcess struct {
	env *relayEnv
	as  *identity.Keypair
}

// postAllowlist drives the control endpoint the way the wire would — a POST
// under this node's certificate, not an MCP call.
func (t inProcess) postAllowlist(ctx context.Context, senders []string) error {
	t.env.as(t.as)
	b, err := json.Marshal(map[string]any{"senders": senders})
	if err != nil {
		return err
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/relay/allowlist", bytes.NewReader(b)).WithContext(ctx)
	t.env.srv.AllowlistHandler().ServeHTTP(w, req)
	if w.Code != 200 {
		return fmt.Errorf("relay: allow-list sync refused (%d)", w.Code)
	}
	return nil
}

func (t inProcess) Call(ctx context.Context, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	t.env.as(t.as)
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var h mcp.ToolHandler
	switch tool {
	case "relay_call":
		h = t.env.srv.relayCall
	case "fetch_queued":
		h = t.env.srv.fetchQueued
	case "ack":
		h = t.env.srv.ack
	}
	return h(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: b}})
}

// AC: A sends while B is down — the envelope is queued at B's relay; B starts,
// fetches, processes it through the real §4.4 pipeline, and acks.
func TestOfflineRecipientReceivesViaRelayAfterDirectFails(t *testing.T) {
	ctx := context.Background()
	e := newRelay(t)
	alice, _ := identity.Generate(identity.AlgoP256)

	// B's own node: store, account, the identifier that opens envelopes
	bst, err := store.OpenSQLite(t.TempDir() + "/bob.db")
	if err != nil {
		t.Fatal(err)
	}
	defer bst.Close()
	if err := bst.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	bobKP, _ := identity.Generate(identity.AlgoP256)
	bacct, _ := bst.CreateAccount(ctx, store.CreateAccountParams{Slug: "bob", DisplayName: "Bob", Algo: "p256"})
	_ = bst.SetAccountKey(ctx, bacct.ID, bobKP.Fingerprint, []byte{1})
	aliceSPKI, _ := x509.MarshalPKIXPublicKey(alice.Signer.Public())
	_, _ = bst.InsertContact(ctx, store.Contact{
		AccountID: bacct.ID, Fingerprint: alice.Fingerprint, SPKI: aliceSPKI,
		Status: "active", Permissions: []string{"message.text"},
	})

	// B publishes this relay and syncs its allow-list (its active contacts)
	bobRelay := &Client{Transport: inProcess{e, bobKP}, PostAllowlist: inProcess{e, bobKP}.postAllowlist}
	if err := bobRelay.SyncAllowlist(ctx, []string{alice.Fingerprint}); err != nil {
		t.Fatal(err)
	}

	// A's direct delivery FAILS (B is down); fallback queues at B's relay.
	env := sealTo(t, alice, bobKP, e.clock, "a-1", 48*time.Hour)
	var rows []string
	var mu sync.Mutex
	fb := Fallback{
		Direct:         func(context.Context) error { return errors.New("dial tcp: connection refused") },
		RelayTransport: inProcess{e, alice},
		Audit:          func(a, r, o string) { mu.Lock(); rows = append(rows, a+" "+r+" "+o); mu.Unlock() },
	}
	path, err := fb.Deliver(ctx, bobKP.Fingerprint, env)
	if err != nil || path != "relay" {
		t.Fatalf("fallback: %s %v", path, err)
	}
	mu.Lock()
	audited := len(rows) == 1 && strings.HasSuffix(rows[0], "queued_at_relay")
	mu.Unlock()
	if !audited {
		t.Fatalf("fallback not audited: %v", rows)
	}

	// B comes up. Time has passed — far outside the 300 s direct window — which
	// is exactly why relay-delivered envelopes are exempt from it (§4.4 step 7).
	e.clock = e.clock.Add(6 * time.Hour)
	ident := &public.Identifier{
		Store:   bst,
		Keypair: func(context.Context, string) (*identity.Keypair, error) { return bobKP, nil },
		Seal:    core.SealRequired, Cert: core.ClientCertOff,
		Now: func() time.Time { return e.clock },
	}
	var processed []string
	bobRelay.Process = func(ctx context.Context, item QueuedItem) error {
		facts, err := ident.OpenSealed(ctx, bacct.ID, bobKP.Fingerprint, public.TransportFacts{}, item.Envelope, public.DeliveryRelay)
		if err != nil {
			return err
		}
		processed = append(processed, facts.From+":"+string(facts.Payload.Params))
		return nil
	}
	n, err := bobRelay.FetchOnce(ctx)
	if err != nil || n != 1 {
		t.Fatalf("fetch: %d %v", n, err)
	}
	if len(processed) != 1 || !strings.HasPrefix(processed[0], alice.Fingerprint+":") || !strings.Contains(processed[0], "send_message") {
		t.Fatalf("processed: %v", processed)
	}
	// acked → deleted from the relay
	if left, _ := e.st.CountRelayQueue(ctx, bobKP.Fingerprint, e.clock.Unix()); left != 0 {
		t.Fatalf("item not acked: %d", left)
	}
	// the SAME envelope delivered directly at this point would be refused as stale
	if _, err := ident.OpenSealed(ctx, bacct.ID, bobKP.Fingerprint, public.TransportFacts{}, env, public.DeliveryDirect); err == nil {
		t.Fatal("a 6-hour-old envelope was accepted on the DIRECT path")
	}
}

func TestFallbackPrefersDirectAndReportsNoRelay(t *testing.T) {
	ctx := context.Background()
	e := newRelay(t)
	alice, _ := identity.Generate(identity.AlgoP256)
	bob, _ := identity.Generate(identity.AlgoP256)

	// direct succeeds → the relay is never touched
	called := false
	fb := Fallback{
		Direct:         func(context.Context) error { called = true; return nil },
		RelayTransport: inProcess{e, alice},
	}
	path, err := fb.Deliver(ctx, bob.Fingerprint, sealTo(t, alice, bob, e.clock, "d-1", time.Hour))
	if err != nil || path != "direct" || !called {
		t.Fatalf("direct path: %s %v", path, err)
	}
	if n, _ := e.st.CountRelayQueue(ctx, bob.Fingerprint, e.clock.Unix()); n != 0 {
		t.Fatal("relay used while direct worked")
	}
	// no relay published: the direct failure stands, named as such
	fb2 := Fallback{Direct: func(context.Context) error { return errors.New("timeout") }}
	if _, err := fb2.Deliver(ctx, bob.Fingerprint, sealTo(t, alice, bob, e.clock, "d-2", time.Hour)); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("no-relay error: %v", err)
	}
	// relay refuses (not allow-listed): the error says so, nothing is lost silently
	fb3 := Fallback{
		Direct:         func(context.Context) error { return errors.New("timeout") },
		RelayTransport: inProcess{e, alice},
	}
	if _, err := fb3.Deliver(ctx, bob.Fingerprint, sealTo(t, alice, bob, e.clock, "d-3", time.Hour)); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("relay refusal: %v", err)
	}
}

func TestFetchLoopBacksOffAndWakesOnPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := newRelay(t)
	bob, _ := identity.Generate(identity.AlgoP256)
	c := &Client{
		Transport: inProcess{e, bob},
		Process:   func(context.Context, QueuedItem) error { return nil },
		Jitter:    func(d time.Duration) time.Duration { return time.Millisecond }, // keep the test fast
	}
	// backoff arithmetic is deterministic and capped
	if got := (&Client{}).next(MinPoll); got < MinPoll || got > 2*MinPoll {
		t.Fatalf("next(MinPoll) = %v", got)
	}
	if got := (&Client{Jitter: func(d time.Duration) time.Duration { return d }}).next(MaxPoll); got != MaxPoll {
		t.Fatalf("cap: %v", got)
	}
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { c.Run(ctx, wake); close(done) }()
	wake <- struct{}{} // the relay's content-free "you have mail"
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
}

var _ = envelope.ErrInvalid

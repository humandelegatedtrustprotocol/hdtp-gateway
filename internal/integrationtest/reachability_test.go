package integrationtest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/public"
	"github.com/tech-sumit/pact-gateway/internal/relay"
)

// relayTransport speaks to an in-process relay Server as one node.
type relayTransport struct {
	srv  *relay.Server
	as   *identity.Keypair
	spki []byte
	mu   *sync.Mutex
}

func (rt relayTransport) Call(ctx context.Context, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	// The lock spans the handler call: Caller is per-connection state on a
	// shared Server, so releasing it early would let two callers' identities
	// cross over if this ever ran concurrently.
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.srv.Caller = func(context.Context) ([]byte, string, bool) { return rt.spki, rt.as.Fingerprint, true }
	return rt.srv.Handler(tool)(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: b}})
}

// postAllowlist drives the relay's control endpoint — plain HTTP over the same
// identity, not a fourth MCP verb (SPEC §10.5).
func (rt relayTransport) postAllowlist(ctx context.Context, senders []string) error {
	b, err := json.Marshal(map[string]any{"senders": senders})
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.srv.Caller = func(context.Context) ([]byte, string, bool) { return rt.spki, rt.as.Fingerprint, true }
	w := httptest.NewRecorder()
	rt.srv.AllowlistHandler().ServeHTTP(w,
		httptest.NewRequest("POST", "/relay/allowlist", bytes.NewReader(b)).WithContext(ctx))
	if w.Code != http.StatusOK {
		return fmt.Errorf("relay: allow-list sync refused (%d)", w.Code)
	}
	return nil
}

// P4 exit (PLAN P4-08): the two reachability paths a node behind NAT actually
// uses — a terminating EDGE (sealed calls survive; nothing else does) and a
// RELAY for a node that is simply not listening — proven end to end against
// real nodes, with the sealed identity doing all the work in both.
func TestP4ExitNATCrossingViaEdgeAndRelay(t *testing.T) {
	ctx := context.Background()
	// alice is behind a terminating edge: seal required, certs never arrive.
	alice := startPactNode(t, "alice", core.SealRequired)
	bob := startPactNode(t, "bob", core.SealRequired)

	// pair them (direct, sealed), then use only NAT-crossing paths
	token, _, err := alice.cm.CreateInvite(ctx, alice.acct.ID, contacts_InviteOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, aliceSPKI := fetchInvite(t, alice.landing.URL, token)
	bobCard, _ := bob.card()
	if _, err := bob.client().SealedCall(ctx,
		outbound.Peer{Endpoint: alice.endpoint, Fingerprint: alice.kp.Fingerprint, Seal: "required"},
		aliceSPKI, "redeem_invite", map[string]any{"token": token, "card": bobCard}, "pair-1"); err != nil {
		t.Fatalf("pairing: %v", err)
	}
	// alice pins bob back (the redemption answer carried her card + key)
	bobSPKI := bob.spki()
	if _, err := bob.st.InsertContact(ctx, store.Contact{
		AccountID: bob.acct.ID, Fingerprint: alice.kp.Fingerprint, SPKI: aliceSPKI,
		Status: "active", Permissions: []string{"message.text"}, PinnedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	// ---- path 1: through a TERMINATING EDGE (cloudflared-shaped) ----
	edge := terminatingEdge(t, alice.srv.URL)
	edgeClient := bob.client()
	edgeClient.Roots = edgeCertPool(t, edge)
	edgePeer := outbound.Peer{Endpoint: edge.URL + "/a/alice/mcp", Fingerprint: alice.kp.Fingerprint, Seal: "required"}
	res, err := edgeClient.SealedCall(ctx, edgePeer, aliceSPKI, "send_message",
		map[string]any{"msg_id": "edge-1", "text": "hello across the edge"}, "edge-1")
	if err != nil || res.IsError {
		t.Fatalf("sealed call across the edge: %v %+v", err, res)
	}
	got := allMessages(t, alice)
	if len(got) != 1 || got[0].ContactFpr != bob.kp.Fingerprint {
		t.Fatalf("edge delivery: %+v", got)
	}
	// the same call unsealed dies at the node's policy gate, not at the edge
	if _, err := edgeClient.CallTool(ctx, edgePeer, "send_message",
		map[string]any{"msg_id": "edge-2", "text": "unsealed"}, outbound.CallOptions{Plaintext: true}); err == nil {
		t.Fatal("unsealed call accepted through the edge")
	}

	// ---- path 2: RELAY, for a node with no inbound path at all ----
	rst, err := store.OpenSQLite(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	defer rst.Close()
	if err := rst.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var callMu sync.Mutex // serializes per-caller identity on the shared Server
	var mu sync.Mutex     // guards the audit rows below
	var relayRows []string
	pings := make(chan string, 4)
	rsrv := &relay.Server{
		Store: rst,
		Audit: func(a, r, o string) { mu.Lock(); relayRows = append(relayRows, a+" "+r+" "+o); mu.Unlock() },
		Notify: func(fpr string) {
			select {
			case pings <- fpr:
			default:
			}
		},
	}
	// bob publishes this relay and syncs his allow-list
	bobRT := relayTransport{rsrv, bob.kp, bobSPKI, &callMu}
	bobRelay := &relay.Client{Transport: bobRT, PostAllowlist: bobRT.postAllowlist}
	if err := bobRelay.SyncAllowlist(ctx, []string{alice.kp.Fingerprint}); err != nil {
		t.Fatal(err)
	}

	// bob goes DARK: his listener stops. Alice's direct delivery fails and she
	// falls back to his relay with the same sealed envelope.
	bob.srv.Close()
	inner, _ := json.Marshal(map[string]any{
		"method": "tools/call",
		"params": map[string]any{"name": "send_message", "arguments": map[string]any{"msg_id": "r-1", "text": "sent while you slept"}},
	})
	bobPub, err := x509.ParsePKIXPublicKey(bobSPKI)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	env, err := envelope.Seal(envelope.SealParams{
		Sender: alice.kp, RecipientPub: bobPub, To: bob.kp.Fingerprint, MsgID: "r-1",
		TS: now.Unix(), Exp: now.Add(48 * time.Hour).Unix(), CTY: "application/pact-call+json",
	}, inner)
	if err != nil {
		t.Fatal(err)
	}
	directTried := false
	fb := relay.Fallback{
		Direct: func(ctx context.Context) error {
			directTried = true
			_, err := alice.client().SealedCall(ctx,
				outbound.Peer{Endpoint: bob.endpoint, Fingerprint: bob.kp.Fingerprint, Seal: "required"},
				bobSPKI, "send_message", map[string]any{"msg_id": "r-1", "text": "sent while you slept"}, "r-1")
			return err
		},
		RelayTransport: relayTransport{rsrv, alice.kp, aliceSPKI, &callMu},
	}
	path, err := fb.Deliver(ctx, bob.kp.Fingerprint, env)
	if err != nil || path != "relay" || !directTried {
		t.Fatalf("fallback: path=%s direct=%v err=%v", path, directTried, err)
	}
	select {
	case fpr := <-pings:
		if fpr != bob.kp.Fingerprint {
			t.Fatalf("ping for %s", fpr)
		}
	default:
		t.Fatal("no you-have-mail ping")
	}

	// bob wakes up and fetches: the envelope goes through the REAL open order
	// with the relay relaxation, and lands in his store.
	ident := &public.Identifier{
		Store:   bob.st,
		Keypair: func(context.Context, string) (*identity.Keypair, error) { return bob.kp, nil },
		Seal:    core.SealRequired, Cert: core.ClientCertOff,
	}
	bobRelay.Process = func(ctx context.Context, item relay.QueuedItem) error {
		facts, err := ident.OpenSealed(ctx, bob.acct.ID, bob.kp.Fingerprint, public.TransportFacts{}, item.Envelope, public.DeliveryRelay)
		if err != nil {
			return err
		}
		out, err := bob.pool.Dispatch(public.WithEnvelopeFacts(ctx, facts), bob.acct.ID, facts.From, facts.Payload)
		if err != nil {
			return err
		}
		if strings.Contains(string(out), "permission_denied") {
			return errors.New("denied")
		}
		return nil
	}
	n, err := bobRelay.FetchOnce(ctx)
	if err != nil || n != 1 {
		t.Fatalf("relay fetch: %d %v", n, err)
	}
	bobMsgs := allMessages(t, bob)
	if len(bobMsgs) != 1 || bobMsgs[0].Body != "sent while you slept" || bobMsgs[0].ContactFpr != alice.kp.Fingerprint {
		t.Fatalf("relayed message: %+v", bobMsgs)
	}
	// acked and gone from the relay; the relay only ever saw metadata
	if left, _ := rst.CountRelayQueue(ctx, bob.kp.Fingerprint, time.Now().Unix()); left != 0 {
		t.Fatalf("queue not drained: %d", left)
	}
	mu.Lock()
	sawQueued := false
	for _, r := range relayRows {
		if strings.Contains(r, "queued") {
			sawQueued = true
		}
		if strings.Contains(strings.ToLower(r), "sent while you slept") {
			t.Fatalf("the relay logged plaintext: %s", r)
		}
	}
	mu.Unlock()
	if !sawQueued {
		t.Fatalf("relay audit: %v", relayRows)
	}
}

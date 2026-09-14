package integrationtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/public"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
)

// terminatingEdge is a Cloudflare-shaped edge: it terminates the caller's TLS
// with its OWN certificate, so client certificates die at the edge, and
// forwards plain HTTP to the node with the adapter's trusted source header.
func terminatingEdge(t *testing.T, nodeURL string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(nodeURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		// The connector reaches the origin inside the owner's trust boundary
		// (cloudflared's own `noTLSVerify` shape) — and it presents NO client
		// certificate, which is the whole point: caller identity dies here.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Header.Set(tunnel.TrustedClientIPHeader("cloudflare"), "198.51.100.7")
			// whatever the caller presented, the node sees no certificate
			r.Out.Header.Del("X-Forwarded-For")
		},
	}
	// the edge speaks TLS to callers with a certificate of its own
	srv := httptest.NewTLSServer(proxy)
	t.Cleanup(srv.Close)
	return srv
}

// P4-05 AC: through a terminating edge, sealed calls succeed, plaintext
// substantive calls fail `seal_required`, and client certificates are ignored.
func TestEdgeModeSealedSucceedsPlaintextRefusedCertsIgnored(t *testing.T) {
	ctx := context.Background()
	// the node is configured EDGE: seal required, client_cert off
	alice := startPactNode(t, "alice", core.SealRequired)
	bob := startPactNode(t, "bob", core.SealOptional)

	// pair them first (direct), then talk only through the edge
	token, _, err := alice.cm.CreateInvite(ctx, alice.acct.ID, contacts_InviteOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, aliceSPKI := fetchInvite(t, alice.landing.URL, token)
	bobCard, _ := bob.card()
	direct := outbound.Peer{Endpoint: alice.endpoint, Fingerprint: alice.kp.Fingerprint, Seal: "required"}
	if _, err := bob.client().SealedCall(ctx, direct, aliceSPKI, "redeem_invite",
		map[string]any{"token": token, "card": bobCard}, "r-1"); err != nil {
		t.Fatalf("pairing: %v", err)
	}

	// now everything goes through the edge: TLS terminates there
	edge := terminatingEdge(t, alice.srv.URL)
	edgePeer := outbound.Peer{
		Endpoint: edge.URL + "/a/alice/mcp", Fingerprint: alice.kp.Fingerprint, Seal: "required",
	}
	edgeRoots := edgeCertPool(t, edge)
	client := bob.client()
	client.Roots = edgeRoots // the edge's WebPKI-ish cert, not alice's key

	// sealed: succeeds, and the node identifies Bob from the ENVELOPE alone
	res, err := client.SealedCall(ctx, edgePeer, aliceSPKI, "send_message",
		map[string]any{"msg_id": "e-1", "text": "through the edge"}, "e-1")
	if err != nil {
		t.Fatalf("sealed call through the edge: %v", err)
	}
	if res.IsError {
		t.Fatalf("sealed call refused: %s", res.Content[0].(*mcp.TextContent).Text)
	}
	msgs := allMessages(t, alice)
	if len(msgs) != 1 || msgs[0].Body != "through the edge" || msgs[0].ContactFpr != bob.kp.Fingerprint {
		t.Fatalf("stored: %+v", msgs)
	}

	// discovery through the edge: a plaintext tools/list arrives with no
	// identity and is answered as to a stranger; the sealed one (SPEC §4.5) is
	// answered for Bob and carries what Alice actually granted him.
	plainList, err := client.ListTools(ctx, edgePeer)
	if err != nil {
		t.Fatalf("plaintext tools/list through the edge: %v", err)
	}
	if has(plainList, "send_message") || !has(plainList, "redeem_invite") {
		t.Fatalf("an identity-less list was not the guest surface: %v", names(plainList))
	}
	sealedList, err := client.SealedListTools(ctx, edgePeer, aliceSPKI, "l-1")
	if err != nil {
		t.Fatalf("sealed tools/list through the edge: %v", err)
	}
	if !has(sealedList, "send_message") || has(sealedList, "redeem_invite") {
		t.Fatalf("the sealed list is not Bob's contact surface: %v", names(sealedList))
	}

	// plaintext substantive call through the edge: refused before it runs
	if _, err := client.CallTool(ctx, edgePeer, "send_message",
		map[string]any{"msg_id": "e-2", "text": "unsealed"}, outbound.CallOptions{Plaintext: true}); err == nil {
		t.Fatal("plaintext accepted by a seal=required node")
	}
	if got := allMessages(t, alice); len(got) != 1 {
		t.Fatalf("an unsealed call was stored: %+v", got)
	}

	// client certificates are IGNORED: the edge terminated TLS, so the node saw
	// none — the sealed identity is the only one, which is exactly why it worked.
	gate := &public.Identifier{Seal: core.SealRequired, Cert: core.ClientCertOff}
	if _, err := gate.PlaintextGateCtx(context.Background(), public.TransportFacts{}, "send_message", true); public.Code(err) != "identity_required" {
		t.Fatalf("edge plaintext with no identity: %v", public.Code(err))
	}
}

// P4-05 AC: with the LAN flag off, a direct (non-tunnel) private-range
// connection is refused AND audited.
func TestLANFlagOffRefusesDirectConnectionsAndAudits(t *testing.T) {
	var mu sync.Mutex
	var rows []string
	guard := public.LANGuard{
		Adapter: "cloudflare", Allow: false,
		TrustedHeader: tunnel.TrustedClientIPHeader("cloudflare"),
		Audit: func(action, resource, outcome string) {
			mu.Lock()
			rows = append(rows, action+" "+resource+" "+outcome)
			mu.Unlock()
		},
	}
	reached := 0
	// The source address is rewritten in front of the guard because a real socket
	// on httptest is always loopback, and loopback is NOT a LAN source (E13): it is
	// where every reverse-tunnel connector delivers from. This test previously
	// dialled loopback and called it "straight from the LAN", which is the exact
	// conflation that left every edge-mode deployment refusing its own connector.
	// What is under test is the guard's CLASSIFICATION, so the address it
	// classifies is what has to vary.
	var fromLAN bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fromLAN {
			r.RemoteAddr = "192.168.1.50:4444"
		}
		guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached++
			w.WriteHeader(200)
		})).ServeHTTP(w, r)
	}))
	defer srv.Close()

	// straight from the LAN, no tunnel header: refused + audited
	fromLAN = true
	resp, err := http.Get(srv.URL + "/a/me/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || reached != 0 {
		t.Fatalf("LAN connection reached the node: %d (handler hits %d)", resp.StatusCode, reached)
	}
	mu.Lock()
	audited := len(rows) == 1 && strings.HasPrefix(rows[0], "lan_refused ") && strings.HasSuffix(rows[0], " denied")
	mu.Unlock()
	if !audited {
		t.Fatalf("refusal not audited: %v", rows)
	}
	// the carrier's own delivery arrives on loopback and must be served (E13):
	// cloudflared, frpc, ngrok and tsnet all dial this bind from this host
	fromLAN = false
	respLoop, err := http.Get(srv.URL + "/a/me/mcp")
	if err != nil {
		t.Fatal(err)
	}
	respLoop.Body.Close()
	if respLoop.StatusCode != 200 {
		t.Fatalf("the connector's own loopback delivery was refused: %d", respLoop.StatusCode)
	}

	// the same LAN connection carrying the adapter's trusted header IS the tunnel
	fromLAN = true
	req, _ := http.NewRequest("GET", srv.URL+"/a/me/mcp", nil)
	req.Header.Set(tunnel.TrustedClientIPHeader("cloudflare"), "203.0.113.4")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 || reached != 2 {
		t.Fatalf("tunneled request refused: %d (handler hits %d)", resp2.StatusCode, reached)
	}
	// flag on → inert, LAN allowed again
	on := guard
	on.Allow = true
	srv2 := httptest.NewServer(on.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })))
	defer srv2.Close()
	resp3, err := http.Get(srv2.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("flag-on refused a LAN connection: %d", resp3.StatusCode)
	}
	// and with no tunnel at all the flag is inert regardless
	off := public.LANGuard{Adapter: "direct", Allow: false}
	srv3 := httptest.NewServer(off.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })))
	defer srv3.Close()
	resp4, err := http.Get(srv3.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != 200 {
		t.Fatalf("direct-mode guard refused: %d", resp4.StatusCode)
	}
}

// P4-05 AC: an endpoint change (mode switch) fans out update_contact.
// AC (P4-05, P7-01): changing the endpoint tells every active contact, and a
// REAL receiving node accepts the announcement — repinning the same identity
// with its new card, keeping the key it had.
//
// This drives the production fan-out (node.AnnounceEndpointChange) end to end
// rather than a loop written in the test: the earlier version proved only that
// a hand-rolled closure could be called.
func TestEndpointChangeFansOutUpdateContact(t *testing.T) {
	ctx := context.Background()
	alice := startPactNode(t, "alice", core.SealOptional)
	bob := startPactNode(t, "bob", core.SealOptional)

	// Bob knows Alice at her CURRENT endpoint, with her key pinned.
	aliceSPKI := alice.spki()
	aliceCard, err := alice.card()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.st.InsertContact(ctx, store.Contact{
		AccountID: bob.acct.ID, Fingerprint: alice.kp.Fingerprint, SPKI: aliceSPKI,
		Status: "active", Card: aliceCard, Permissions: []string{"message.text"},
		PinnedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	// ...and Alice knows Bob, at his real listener, so the announcement can
	// actually reach him.
	bobCard, err := bob.card()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.st.InsertContact(ctx, store.Contact{
		AccountID: alice.acct.ID, Fingerprint: bob.kp.Fingerprint, SPKI: bob.spki(),
		Status: "active", Card: bobCard, Permissions: []string{"message.text"},
		PinnedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	// Alice moves. The announcement carries her new card and a signature over
	// her unchanged fingerprint, made with the key Bob pinned.
	const moved = "https://pact.example.com"
	newCard, err := contacts.BuildCard(contacts.Card{
		FN: alice.acct.DisplayName, Endpoint: moved + "/a/alice/mcp",
		Key: alice.kp.Fingerprint, Seal: string(alice.seal),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := identity.SignBytes(alice.kp, []byte(alice.kp.Fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	res, err := alice.client().CallTool(ctx,
		outbound.Peer{Endpoint: bob.endpoint, Fingerprint: bob.kp.Fingerprint},
		"update_contact", map[string]any{
			"card": newCard, "sig": base64.RawURLEncoding.EncodeToString(sig),
		}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatalf("update_contact: %v", err)
	}
	if res.IsError {
		t.Fatalf("a real node refused the endpoint announcement: %s", res.Content[0].(*mcp.TextContent).Text)
	}

	// Bob repinned the SAME identity at the new endpoint, and still holds her key.
	got, err := bob.st.GetContact(ctx, bob.acct.ID, alice.kp.Fingerprint)
	if err != nil {
		t.Fatalf("Alice fell out of Bob's contacts: %v", err)
	}
	if !strings.Contains(got.Card, moved) {
		t.Fatalf("Bob still has the old endpoint:\n%s", got.Card)
	}
	if len(got.SPKI) == 0 {
		t.Fatal("the repin wiped the pinned key: Bob can no longer seal to Alice")
	}
	if got.Status != "active" || len(got.Permissions) != 1 {
		t.Fatalf("the repin damaged the relationship: %+v", got)
	}

	// A forged announcement — right card, wrong signer — changes nothing.
	mallory, _ := identity.Generate(identity.AlgoP256)
	forged, _ := identity.SignBytes(mallory, []byte(alice.kp.Fingerprint))
	bad, err := alice.client().CallTool(ctx,
		outbound.Peer{Endpoint: bob.endpoint, Fingerprint: bob.kp.Fingerprint},
		"update_contact", map[string]any{
			"card": aliceCard, "sig": base64.RawURLEncoding.EncodeToString(forged),
		}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bad.IsError {
		t.Fatal("a card signed by the wrong key moved a contact's endpoint")
	}
	again, _ := bob.st.GetContact(ctx, bob.acct.ID, alice.kp.Fingerprint)
	if !strings.Contains(again.Card, moved) {
		t.Fatal("the refused announcement still changed the stored card")
	}
}

/* ------------------------------ helpers ------------------------------ */

func contacts_InviteOptions() contacts.InviteOptions {
	return contacts.InviteOptions{AutoAccept: true, MaxUses: 1, Preset: "friend", Label: "edge"}
}

func edgeCertPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func allMessages(t *testing.T, n *pactNode) []store.Message {
	t.Helper()
	ctx := context.Background()
	threads, _ := n.st.ListThreadsByAccount(ctx, n.acct.ID)
	var out []store.Message
	for _, th := range threads {
		msgs, _ := n.msg.Thread(ctx, n.acct.ID, th.ID)
		out = append(out, msgs...)
	}
	return out
}

func has(tools []*mcp.Tool, name string) bool {
	for _, t := range tools {
		if t.Name == name {
			return true
		}
	}
	return false
}

func names(tools []*mcp.Tool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return out
}

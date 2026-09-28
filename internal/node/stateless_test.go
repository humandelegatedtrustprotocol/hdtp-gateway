package node

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// wireLog records what reaches a node's public listener: each request's method, its JSON-RPC
// method, the MCP-Protocol-Version it declared, and whether either side named a session.
type wireLog struct {
	mu   sync.Mutex
	seen []wireRequest
}

type wireRequest struct {
	HTTP, RPC, Version string
	Status             int
	Session            bool
}

// statusWriter keeps the status a handler answered with.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (l *wireLog) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		var rpc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &rpc)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		l.mu.Lock()
		l.seen = append(l.seen, wireRequest{HTTP: r.Method, RPC: rpc.Method, Version: r.Header.Get("Mcp-Protocol-Version"),
			Status: sw.status, Session: r.Header.Get("Mcp-Session-Id") != "" || w.Header().Get("Mcp-Session-Id") != ""})
		l.mu.Unlock()
	})
}

func (l *wireLog) take() []wireRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.seen
	l.seen = nil
	return out
}

// A sealed call completes against the stateless public surface from a client of either MCP era
// (SPEC §5.5): the node's own outbound client, which speaks 2026-07-28 (`server/discover`, then the
// call, each a POST of its own), and a client of the handshake revisions (2025-11-25). Neither
// exchange names a session, and the outbound client sends nothing but those two POSTs: no
// standalone GET, no DELETE when it closes. The handshake-era client does try the standalone GET
// its revision allows, and is answered 405, which it takes as "no stream" and carries on.
func TestASealedCallCompletesFromEitherMCPEra(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Now()}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 30)

	// Alina's listener, with every request recorded.
	var wire wireLog
	srv := httptest.NewUnstartedServer(wire.wrap(alina.n.Handler()))
	srv.TLS = alina.n.srv.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dn.set(alina.host, srv.Listener.Addr().String())

	peerA := outbound.Peer{Endpoint: alina.endpoint(), Seal: "required", Root: alina.rootFpr(), Leaf: alina.leaf()}
	clientB, err := bharat.n.OutboundClient(bharat.acct.ID)
	if err != nil {
		t.Fatal(err)
	}

	// --- 2026-07-28: the node's own outbound client ---
	res, err := clientB.SealedCall(ctx, peerA, "redeem_invite", map[string]any{"token": alina.invite(true), "card": bharat.card()}, "redeem-b")
	if err != nil || res.IsError {
		t.Fatalf("redeem over 2026-07-28: %v %+v", err, res)
	}
	got := wire.take()
	var rpcs []string
	for _, r := range got {
		if r.HTTP != http.MethodPost || r.Session {
			t.Fatalf("the outbound client's exchange was not two sessionless POSTs: %+v", got)
		}
		rpcs = append(rpcs, r.RPC+"@"+r.Version)
	}
	if strings.Join(rpcs, " ") != "server/discover@2026-07-28 tools/call@2026-07-28" {
		t.Fatalf("the outbound client sent %v, want server/discover then tools/call, both 2026-07-28", rpcs)
	}
	if c, err := alina.st.GetContact(ctx, alina.acct.ID, bharat.rootFpr()); err != nil || c.Status != "active" {
		t.Fatalf("the redemption answered and made no contact: %v %+v", err, c.Status)
	}

	// --- 2025-11-25: a client of the handshake revisions, sealing a send_message by hand ---
	hc, err := clientB.HTTPClient(peerA)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "legacy", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: peerA.Endpoint, HTTPClient: hc},
		&mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal(err)
	}
	if v := cs.InitializeResult().ProtocolVersion; v != "2025-11-25" {
		t.Fatalf("the legacy client negotiated %q", v)
	}
	sender, err := identity.ToLib(bharat.kp())
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := pactidentity.ParseSPKI(alina.leafSPKI())
	if err != nil {
		t.Fatal(err)
	}
	now := clock.now()
	env, err := pactidentity.SealRequest(pactidentity.SealOpts{
		RecipientKey: recipient, Sender: sender, Form: "chain", SenderChain: [][]byte{bharat.leaf(), bharat.rc},
		Method: "tools/call", Params: json.RawMessage(`{"name":"send_message","arguments":{"msg_id":"legacy-1","text":"over the handshake era"}}`),
		MsgID: "legacy-1", TS: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "sealed_call",
		Arguments: map[string]any{"protected": env.Protected, "enc": env.Enc, "ct": env.Ct, "sig": env.Sig}})
	if err != nil || sealed.IsError {
		t.Fatalf("sealed_call over 2025-11-25: %v %+v", err, sealed)
	}
	var answer pactidentity.Envelope
	if err := json.Unmarshal([]byte(sealed.Content[0].(*mcp.TextContent).Text), &answer); err != nil {
		t.Fatal(err)
	}
	opened, err := pactidentity.OpenResult(answer, pactidentity.OpenOpts{
		Recipient: sender, MsgID: "legacy-1", Now: now,
		Pins:         []pactidentity.Pin{{Root: peerA.Root, Endpoint: peerA.Endpoint, Leaf: pactidentity.B64url(peerA.Leaf), State: "active"}},
		ExpectedRoot: peerA.Root, ExpectedEndpoint: peerA.Endpoint,
	})
	if err != nil || opened.Error != nil {
		t.Fatalf("the sealed answer did not open as a result: %v %s", err, opened.Error)
	}
	_ = cs.Close()
	if !alina.received("over the handshake era") {
		t.Fatal("the legacy-era sealed send_message answered and stored nothing")
	}
	var legacy []string
	for _, r := range wire.take() {
		if r.Session || (r.HTTP != http.MethodPost && r.Status != http.StatusMethodNotAllowed) {
			t.Fatalf("the legacy exchange carried a session, or a non-POST was served: %+v", r)
		}
		legacy = append(legacy, r.HTTP+" "+r.RPC)
	}
	if !strings.Contains(strings.Join(legacy, ","), "POST initialize") || !strings.Contains(strings.Join(legacy, ","), "POST tools/call") {
		t.Fatalf("the legacy client did not handshake and call: %v", legacy)
	}
}

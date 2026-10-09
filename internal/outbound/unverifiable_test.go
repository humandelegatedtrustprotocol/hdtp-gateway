package outbound

// An answer this caller cannot verify — signed by a leaf it holds no pin for — and what the
// client does next, by the peer's seal policy (HDTP §13.2, §13.4, §14.3). The peer here has
// renewed: it answers under a leaf the caller never pinned, and the caller's pin is the old one.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// renewedPeer is an identity that has renewed its leaf after the caller pinned it: the server
// presents and signs under the new leaf; `pin` is the leaf the caller still holds.
type renewedPeer struct {
	root     string
	endpoint string
	pin      []byte
	leaf     []byte
	calls    map[string]int
	form     string
	addr     string
}

// startRenewedPeer issues a second leaf under the test identity's root, newer than the one the
// caller pinned, and serves `sealed_call` and `get_card` under it over TLS. Every sealed_call is
// answered with one result sealed to the caller's key, in the form `p.form` names; get_card
// answers the current chain in plaintext.
func startRenewedPeer(t *testing.T, id *testIdentity, caller *testIdentity) *renewedPeer {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := identity.ToLib(kp)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{
		CN: "Alina", RootCN: "Alina", RootKey: id.root, HostPub: lib.Public(), Endpoint: id.endpoint,
		NotBefore: time.Now().Add(-30 * time.Minute), NotAfter: time.Now().Add(300 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	callerPub, err := identity.PublicOf(caller.kp)
	if err != nil {
		t.Fatal(err)
	}
	p := &renewedPeer{root: id.rootFpr, endpoint: id.endpoint, pin: id.leaf, leaf: leaf, calls: map[string]int{}, form: "leaf"}
	chain := [][]byte{leaf, id.rootCert}
	srv := mcp.NewServer(&mcp.Implementation{Name: "alina", Version: "1"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "sealed_call", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			p.calls["sealed_call"]++
			protected, _ := args["protected"].(string)
			hdr, err := hdtpidentity.DecodeB64url(protected)
			if err != nil {
				t.Errorf("sealed_call: protected: %v", err)
			}
			var h struct {
				MsgID string `json:"msg_id"`
			}
			_ = json.Unmarshal(hdr, &h)
			inner, _ := json.Marshal(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"status":"delivered"}`}}})
			now := time.Now()
			env, err := hdtpidentity.SealResult(hdtpidentity.SealOpts{
				RecipientKey: callerPub, Sender: lib, Form: p.form, SenderChain: chain, Result: inner,
				MsgID: h.MsgID, TS: now.Unix(), Exp: now.Add(10 * time.Minute).Unix(),
			})
			if err != nil {
				t.Errorf("sealed_call: seal: %v", err)
				return nil, nil, err
			}
			body, _ := json.Marshal(env)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "get_card", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
			p.calls["get_card"]++
			body, _ := json.Marshal(map[string]any{"card": "", "card_sig": "", "chain": []string{hdtpidentity.B64url(leaf), hdtpidentity.B64url(id.rootCert)}})
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
		})
	// The listener is loopback and the dialled Host is not, which the SDK refuses unless told
	// otherwise — as the node tells it (node.go, its own handler).
	ts := httptest.NewUnstartedServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: kp.Signer}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	p.addr = ts.Listener.Addr().String()
	return p
}

// peer is the caller's view: pinned by the root, holding the OLD leaf, under the given policy.
func (p *renewedPeer) peer(seal string) Peer {
	return Peer{Endpoint: p.endpoint, Seal: seal, Root: p.root, Leaf: p.pin, ChainSeen: true}
}

// callerTo is a client whose dials all reach the peer's listener, recording every re-pin.
func callerTo(t *testing.T, me *testIdentity, p *renewedPeer, repinned *[][]byte) *Client {
	t.Helper()
	c := me.client()
	c.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, p.addr)
	}
	c.OnRepin = func(_ Peer, leaf, _ []byte) { *repinned = append(*repinned, leaf) }
	return c
}

func TestAnUnverifiableAnswerFromARequiredPeerIsNotFollowedByAPlaintextGetCard(t *testing.T) {
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	var repinned [][]byte
	c := callerTo(t, bharat, p, &repinned)

	// Alina answers under her new leaf by its fingerprint alone (she has recorded her chain as
	// sent to Bharat); Bharat's pin is her old leaf, so the answer names a leaf he does not hold.
	_, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-required")
	if err == nil || !strings.Contains(err.Error(), "unverifiable answer: unknown leaf") {
		t.Fatalf("want the unverifiable answer reported, got %v", err)
	}
	// A plaintext get_card to a peer that requires sealing is refused before it leaves, every
	// time: a remedy that cannot work is not tried, and the error does not blame its refusal.
	if strings.Contains(err.Error(), "get_card") || strings.Contains(err.Error(), "seal_required") {
		t.Fatalf("the error blames a get_card nothing could have made succeed: %v", err)
	}
	if !strings.Contains(err.Error(), "the pin stands") {
		t.Fatalf("the error must say what the caller is left with: %v", err)
	}
	if p.calls["get_card"] != 0 {
		t.Fatalf("%d plaintext get_card call(s) reached a peer that requires sealing", p.calls["get_card"])
	}
	if p.calls["sealed_call"] != 1 {
		t.Fatalf("%d sealed_call(s), want the one attempt and no retry", p.calls["sealed_call"])
	}
	if len(repinned) != 0 {
		t.Fatalf("the pin moved on an answer nothing verified: %d re-pin(s)", len(repinned))
	}
}

func TestAnUnverifiableAnswerFromAnOptionalPeerIsFollowedByOnePlaintextGetCard(t *testing.T) {
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	var repinned [][]byte
	c := callerTo(t, bharat, p, &repinned)

	// The one case the plaintext get_card alone serves: the peer takes plaintext, and its sealed
	// answer carried no chain. The chain get_card answers validates to the pinned root at the
	// dialed address and is newer than the pin, so the pin moves and the call is retried once.
	res, err := c.SealedCall(context.Background(), p.peer("optional"), "send_message", map[string]any{"text": "hi"}, "m-optional")
	if err != nil {
		t.Fatalf("the call must recover through get_card: %v", err)
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || tc.Text != `{"status":"delivered"}` {
		t.Fatalf("the retried call's result was not returned: %+v", res.Content[0])
	}
	if p.calls["get_card"] != 1 {
		t.Fatalf("%d get_card call(s), want exactly one", p.calls["get_card"])
	}
	if p.calls["sealed_call"] != 2 {
		t.Fatalf("%d sealed_call(s), want the attempt and one retry", p.calls["sealed_call"])
	}
	if len(repinned) != 1 || string(repinned[0]) != string(p.leaf) {
		t.Fatalf("the pin must move to the leaf get_card's chain carried, once: %d re-pin(s)", len(repinned))
	}
}

func TestAnAnswerCarryingTheRenewedChainRepinsWithoutGetCard(t *testing.T) {
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	p.form = "chain"
	var repinned [][]byte
	c := callerTo(t, bharat, p, &repinned)

	// The control, and the sealed path's own delivery of a renewal (§13.2, §14.3): the first
	// answer after it carries the chain, which validates to the pinned root at the dialed address
	// and is newer than the pin. The pin follows as the answer passes; nothing else is asked.
	res, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-chain")
	if err != nil {
		t.Fatalf("an answer carrying the chain must verify: %v", err)
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || tc.Text != `{"status":"delivered"}` {
		t.Fatalf("the result was not returned: %+v", res.Content[0])
	}
	if p.calls["get_card"] != 0 || p.calls["sealed_call"] != 1 {
		t.Fatalf("calls %v, want one sealed_call and no get_card", p.calls)
	}
	if len(repinned) != 1 || string(repinned[0]) != string(p.leaf) {
		t.Fatalf("the pin must follow the chain the answer carried, once: %d re-pin(s)", len(repinned))
	}
}

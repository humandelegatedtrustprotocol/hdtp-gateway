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
// presents and signs under the new leaf, and still opens what is sealed to the old one, which it
// keeps until its notAfter (§14.4); `pin` is the leaf the caller still holds.
type renewedPeer struct {
	root     string
	endpoint string
	pin      []byte
	leaf     []byte
	calls    map[string]int
	// form is the form every answer but get_card's is sealed in; cardForm is get_card's. A
	// responder answers get_card with the chain whatever its record says (§13.2); a test sets
	// cardForm to "leaf" to stand in for one that answers it by the record.
	form, cardForm string
	// retireAfter names the tool whose sealed answer retires the pinned key as it goes: the key moves
	// from the held keys to the former ones, and an envelope sealed to it from then on is answered
	// certificate_renewed with the current chain, in plaintext (§14.4).
	retireAfter string
	addr        string
	state       hdtpidentity.NodeState
}

// startRenewedPeer issues a second leaf under the test identity's root, newer than the one the
// caller pinned, and serves `sealed_call` and `get_card` under it over TLS. Every sealed_call is
// opened — under the old key or the new — and answered with one result sealed to the caller's key,
// in `p.form` or, for an inner get_card, `p.cardForm`; the plaintext get_card answers the current
// chain. The handlers count every call by tool, the sealed ones as `sealed <tool>`.
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
	p := &renewedPeer{root: id.rootFpr, endpoint: id.endpoint, pin: id.leaf, leaf: leaf, calls: map[string]int{}, form: "leaf", cardForm: "chain"}
	chain := [][]byte{leaf, id.rootCert}
	chainB64 := []string{hdtpidentity.B64url(leaf), hdtpidentity.B64url(id.rootCert)}
	p.state = hdtpidentity.NodeState{
		Endpoint: id.endpoint, AcceptNewHosts: "auto", Chain: chainB64,
		Keys: []hdtpidentity.HeldKey{
			{Kid: id.kp.Fingerprint, Leaf: hdtpidentity.B64url(id.leaf), PKCS8: hdtpidentity.B64url(pkcs8Of(t, id.kp)), Current: false},
			{Kid: kp.Fingerprint, Leaf: hdtpidentity.B64url(leaf), PKCS8: hdtpidentity.B64url(pkcs8Of(t, kp)), Current: true},
		},
		Pins: []hdtpidentity.Pin{{Root: caller.rootFpr, Endpoint: caller.endpoint, Leaf: hdtpidentity.B64url(caller.leaf), State: "active"}},
	}
	card := func() string {
		body, _ := json.Marshal(map[string]any{"card": "", "card_sig": "", "chain": chainB64})
		return string(body)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "alina", Version: "1"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "sealed_call", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			p.calls["sealed_call"]++
			raw, _ := json.Marshal(args)
			var env hdtpidentity.Envelope
			_ = json.Unmarshal(raw, &env)
			d, err := hdtpidentity.Decide(time.Now(), env, p.state)
			if err == nil && d.Result["code"] == "certificate_renewed" {
				p.calls["certificate_renewed"]++
				body, _ := json.Marshal(map[string]any{"code": "certificate_renewed", "data": d.Result["data"]})
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
			}
			if err != nil || d.Result["code"] != "ok" {
				t.Errorf("sealed_call did not open: %v %v", err, d.Result)
				return nil, nil, err
			}
			params, _ := d.Result["params"].(map[string]any)
			tool, _ := params["name"].(string)
			p.calls["sealed "+tool]++
			form, inner := p.form, `{"status":"delivered"}`
			if tool == "get_card" {
				form, inner = p.cardForm, card()
			}
			protected, _ := hdtpidentity.DecodeB64url(env.Protected)
			var h struct {
				MsgID string `json:"msg_id"`
			}
			_ = json.Unmarshal(protected, &h)
			result, _ := json.Marshal(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: inner}}})
			now := time.Now()
			out, err := hdtpidentity.SealResult(hdtpidentity.SealOpts{
				RecipientKey: callerPub, Sender: lib, Form: form, SenderChain: chain, Result: result,
				MsgID: h.MsgID, TS: now.Unix(), Exp: now.Add(10 * time.Minute).Unix(),
			})
			if err != nil {
				t.Errorf("sealed_call: seal: %v", err)
				return nil, nil, err
			}
			if tool == p.retireAfter {
				p.state.Keys = p.state.Keys[1:]
				p.state.Former = append(p.state.Former, id.kp.Fingerprint)
			}
			body, _ := json.Marshal(out)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "get_card", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
			p.calls["get_card"]++
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: card()}}}, nil, nil
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

// pkcs8Of is the keypair's private key as the library's NodeState holds one.
func pkcs8Of(t *testing.T, kp *identity.Keypair) []byte {
	t.Helper()
	der, err := identity.MarshalPKCS8(kp)
	if err != nil {
		t.Fatal(err)
	}
	return der
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

// delivered fails the test unless res is the retried call's result.
func delivered(t *testing.T, res *mcp.CallToolResult) {
	t.Helper()
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || tc.Text != `{"status":"delivered"}` {
		t.Fatalf("the retried call's result was not returned: %+v", res.Content[0])
	}
}

func TestAnUnverifiableAnswerFromARequiredPeerIsFollowedByOneSealedGetCard(t *testing.T) {
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	var repinned [][]byte
	c := callerTo(t, bharat, p, &repinned)

	// Alina answers under her new leaf by its fingerprint alone (she has recorded her chain as
	// sent to Bharat); Bharat's pin is her old leaf, so the answer names a leaf he does not hold.
	// A plaintext get_card is refused by a peer that requires sealing before it is read, so the
	// one asked is sealed — to the pinned leaf, whose key Alina keeps until it expires (§14.4) —
	// and get_card's answer carries the chain whatever her record says (§13.2). The chain
	// validates to the pinned root at the dialed address and is newer than the pin: the pin moves,
	// and the call is retried once.
	res, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-required")
	if err != nil {
		t.Fatalf("the call must recover through a sealed get_card: %v", err)
	}
	delivered(t, res)
	if p.calls["get_card"] != 0 {
		t.Fatalf("%d plaintext get_card call(s) reached a peer that requires sealing", p.calls["get_card"])
	}
	if p.calls["sealed get_card"] != 1 {
		t.Fatalf("%d sealed get_card call(s), want exactly one", p.calls["sealed get_card"])
	}
	if p.calls["sealed send_message"] != 2 || p.calls["sealed_call"] != 3 {
		t.Fatalf("calls %v, want the attempt, one sealed get_card and one retry", p.calls)
	}
	if len(repinned) != 1 || string(repinned[0]) != string(p.leaf) {
		t.Fatalf("the pin must move to the leaf get_card's chain carried, once: %d re-pin(s)", len(repinned))
	}
}

func TestAnUnverifiableAnswerFromARequiredPeerWhoseGetCardAnswersByTheRecordFailsNamingBoth(t *testing.T) {
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	// A responder that answers get_card in the form its record says, under the unknown leaf: the
	// sealed get_card fails as the call did, nothing is retried, and the error says what was tried.
	p.cardForm = "leaf"
	var repinned [][]byte
	c := callerTo(t, bharat, p, &repinned)

	_, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-required-stuck")
	if err == nil {
		t.Fatal("an answer nothing verified, and a get_card answered the same way, must fail the call")
	}
	for _, want := range []string{"unverifiable answer: unknown leaf", "a sealed get_card", "unknown leaf"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must say %q — what failed and what was tried: %v", want, err)
		}
	}
	if p.calls["get_card"] != 0 {
		t.Fatalf("%d plaintext get_card call(s) reached a peer that requires sealing", p.calls["get_card"])
	}
	if p.calls["sealed get_card"] != 1 || p.calls["sealed send_message"] != 1 {
		t.Fatalf("calls %v, want the attempt and one sealed get_card, no retry", p.calls)
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

	// A peer that takes plaintext is asked in plaintext, which reaches it without a key to seal to.
	// The chain get_card answers validates to the pinned root at the dialed address and is newer
	// than the pin, so the pin moves and the call is retried once.
	res, err := c.SealedCall(context.Background(), p.peer("optional"), "send_message", map[string]any{"text": "hi"}, "m-optional")
	if err != nil {
		t.Fatalf("the call must recover through get_card: %v", err)
	}
	delivered(t, res)
	if p.calls["get_card"] != 1 || p.calls["sealed get_card"] != 0 {
		t.Fatalf("calls %v, want exactly one plaintext get_card and no sealed one", p.calls)
	}
	if p.calls["sealed send_message"] != 2 {
		t.Fatalf("%d sealed send_message(s), want the attempt and one retry", p.calls["sealed send_message"])
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
	delivered(t, res)
	if p.calls["get_card"] != 0 || p.calls["sealed get_card"] != 0 || p.calls["sealed_call"] != 1 {
		t.Fatalf("calls %v, want one sealed_call and no get_card of either kind", p.calls)
	}
	if len(repinned) != 1 || string(repinned[0]) != string(p.leaf) {
		t.Fatalf("the pin must follow the chain the answer carried, once: %d re-pin(s)", len(repinned))
	}
}

func TestASealedGetCardAnsweredCertificateRenewedFailsTheCallAndTheNextCallFollowsIt(t *testing.T) {
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	// The pinned key retires between the attempt and the get_card: the attempt opens under it and
	// is answered under the unknown leaf; the sealed get_card, sealed to the same key, is refused
	// certificate_renewed in plaintext before it opens.
	p.retireAfter = "send_message"
	var repinned [][]byte
	c := callerTo(t, bharat, p, &repinned)

	_, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "hi"}, "m-retired")
	if err == nil {
		t.Fatal("a sealed get_card answered certificate_renewed must fail the call")
	}
	for _, want := range []string{"unverifiable answer: unknown leaf", "a sealed get_card", "certificate_renewed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must say %q: %v", want, err)
		}
	}
	if len(repinned) != 0 {
		t.Fatalf("the pin moved on a call that failed: %d re-pin(s)", len(repinned))
	}
	if p.calls["sealed get_card"] != 0 || p.calls["certificate_renewed"] != 1 || p.calls["sealed send_message"] != 1 {
		t.Fatalf("calls %v, want the attempt and one get_card refused certificate_renewed before it opened", p.calls)
	}

	// The pin stands, so the next call seals to the retired key again: its first attempt is answered
	// certificate_renewed, whose chain it follows to the current leaf, and delivers.
	res, err := c.SealedCall(context.Background(), p.peer("required"), "send_message", map[string]any{"text": "again"}, "m-after-retired")
	if err != nil {
		t.Fatalf("the next call must follow certificate_renewed: %v", err)
	}
	delivered(t, res)
	if p.calls["certificate_renewed"] != 2 || p.calls["sealed send_message"] != 2 || p.calls["sealed get_card"] != 0 {
		t.Fatalf("calls %v, want the second call's attempt answered certificate_renewed and one re-sealed send_message", p.calls)
	}
	if len(repinned) != 1 || string(repinned[0]) != string(p.leaf) {
		t.Fatalf("the pin must follow the renewed chain once: %d re-pin(s)", len(repinned))
	}
}

package node

// The guest total on the node, end to end (the owner's decision of 2026-09-29,
// docs/release/two-layer-limits-2026-09-28.md §6): the shipped handler, the real limits sidecar
// with a total of its own, and callers at addresses of their own — strangers arrive through the
// proxy the node trusts (proxy_address), which names each one's address, and the contact over the
// node's own TLS from loopback.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// totalRig is two demo nodes, alina behind a proxy at proxyAddr with a small guest total, and bharat
// her contact.
type totalRig struct {
	t       *testing.T
	clock   *demoClock
	alina   *demoNode
	bharat  *demoNode
	total   int
	reads   int
	msg     int
	contact *outbound.Client
	peerA   outbound.Peer
}

const proxyAddr = "10.9.9.9"

func newTotalRig(t *testing.T) *totalRig {
	// The rig's clock starts at the real time, not a fixed date: the strangers' certificates come from
	// testid, which issues them from time.Now() (valid from an hour before it). A clock fixed at
	// 2026-09-29 12:00 UTC made every stranger's leaf not yet valid from 13:00 UTC that day, and the
	// test failed 30 times in 30 from then on.
	clock := &demoClock{t: time.Now().UTC().Truncate(time.Second)}
	dn := &demoNet{hosts: map[string]string{}}
	r := &totalRig{t: t, clock: clock, alina: startDemoNode(t, clock, dn, "alina", "Alina Rao", 365), bharat: startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)}
	rules := limitstest.DefaultRules(t)
	rules.GuestTotalCallsPerHour = 3
	r.total = int(rules.GuestTotalCallsPerHour)
	n := r.alina.n
	n.opts.Limits = limitstest.Start(t, rules).Client
	n.srv.ProxyAddress = proxyAddr
	// Every read of alina's keys, counted: a call refused before the open reads none.
	n.mu.RLock()
	ident := n.accounts[r.alina.acct.ID].ident
	n.mu.RUnlock()
	load := ident.RecipientState
	ident.RecipientState = func(ctx context.Context) (*public.RecipientState, error) {
		r.reads++
		return load(ctx)
	}
	r.alina.pinPeer(r.bharat)
	r.contact = r.bharat.n.wireClient(r.bharat.acct.ID, &outbound.Client{Keypair: r.bharat.kp(), Cert: tlsCertOf(r.bharat.kp())})
	r.peerA = outbound.Peer{Endpoint: r.alina.endpoint(), Seal: "required", Root: r.alina.rootFpr(), Leaf: r.alina.leaf()}
	return r
}

// contactCalls is bharat's get_card over the node's TLS, from loopback; nil when it was answered.
func (r *totalRig) contactCalls() error {
	r.msg++
	res, err := r.contact.Call(context.Background(), r.peerA, "get_card", map[string]any{}, fmt.Sprintf("card-%d", r.msg))
	if err != nil {
		return err
	}
	if res.IsError {
		return fmt.Errorf("refused: %s", textOf(res))
	}
	return nil
}

// seal is a sealed tools/call to alina from a host's key and chain.
func (r *totalRig) seal(sender *hdtpidentity.PrivateKey, chain [][]byte, form, tool string, args map[string]any) *hdtpidentity.Envelope {
	r.t.Helper()
	leaf, err := hdtpidentity.Parse(r.alina.leaf())
	if err != nil {
		r.t.Fatal(err)
	}
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": args})
	r.msg++
	env, err := hdtpidentity.SealRequest(hdtpidentity.SealOpts{
		RecipientKey: leaf.PublicKey, Sender: sender, Form: form, SenderChain: chain, Method: "tools/call", Params: params,
		MsgID: fmt.Sprintf("m-%d", r.msg), TS: r.clock.now().Unix(), Exp: r.clock.now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

// stranger is a fresh root and a host under it.
func (r *totalRig) stranger(i int) *testid.Host {
	return testid.NewWallet(r.t, fmt.Sprintf("Stranger%d", i)).Issue(r.t, fmt.Sprintf("https://stranger%d.test/a/s/mcp", i))
}

// post delivers a sealed_call to alina's shipped handler from remote (host:port), naming source
// when remote is the proxy, and answers the clear refusal's code, or "sealed" for an answer sealed
// back to the caller.
func (r *totalRig) post(remote, source string, env *hdtpidentity.Envelope) (answer string, retryAfter int) {
	r.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": public.SealedToolName, "arguments": env}})
	req := httptest.NewRequest(http.MethodPost, "https://"+r.alina.host+"/a/"+r.alina.slug+"/mcp", strings.NewReader(string(body)))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if source != "" {
		req.Header.Set(public.ProxyAddressHeader, source)
	}
	rec := httptest.NewRecorder()
	r.alina.n.Handler().ServeHTTP(rec, req)
	payload := rec.Body.String()
	for _, line := range strings.Split(payload, "\n") {
		if rest, ok := strings.CutPrefix(line, "data:"); ok {
			payload = strings.TrimSpace(rest)
		}
	}
	var rpc struct {
		Result mcp.CallToolResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(payload), &rpc); err != nil || len(rpc.Result.Content) == 0 {
		r.t.Fatalf("an answer that does not read: %d %s", rec.Code, rec.Body.String())
	}
	text := rpc.Result.Content[0].(*mcp.TextContent).Text
	var clear struct {
		Code       string `json:"code"`
		RetryAfter int    `json:"retry_after"`
	}
	if json.Unmarshal([]byte(text), &clear) == nil && clear.Code != "" {
		return clear.Code, clear.RetryAfter
	}
	var sealed hdtpidentity.Envelope
	if json.Unmarshal([]byte(text), &sealed) == nil && sealed.Protected != "" {
		return "sealed", 0
	}
	r.t.Fatalf("an answer neither refused in the clear nor sealed: %s", text)
	return "", 0
}

func (r *totalRig) audited(s string) bool {
	return strings.Contains(strings.Join(r.alina.log, "\n"), s)
}

func TestAStrangerFloodDrainsTheTotalThenIsRefusedBeforeTheOpenAndAKnownContactGetsThrough(t *testing.T) {
	r := newTotalRig(t)
	proxy := proxyAddr + ":40000"
	// The contact calls from its own address first: answered, and that address is known from here.
	if err := r.contactCalls(); err != nil {
		t.Fatalf("the contact's first call: %v", err)
	}
	// Strangers, each from an address of its own, spend the total after the open: each is let
	// through to the open and answered, sealed.
	for i := range r.total {
		h := r.stranger(i)
		if got, _ := r.post(proxy, fmt.Sprintf("203.0.113.%d", i+1), r.seal(h.Key, h.Chain, "chain", "request_contact", map[string]any{"card": h.Card("Stranger", "required")})); got != "sealed" {
			t.Fatalf("stranger %d, with the total holding a call: %s", i, got)
		}
	}
	// Spent. Fresh roots from fresh addresses are refused before the open: in the clear, with the
	// total's wait, and alina's keys not read.
	reads := r.reads
	for i := 10; i < 15; i++ {
		h := r.stranger(i)
		got, wait := r.post(proxy, fmt.Sprintf("203.0.113.%d", i+1), r.seal(h.Key, h.Chain, "chain", "request_contact", map[string]any{"card": h.Card("Stranger", "required")}))
		if got != "rate_limited" || wait < 1 {
			t.Fatalf("stranger %d past the total: %s retry_after %d", i, got, wait)
		}
	}
	if r.reads != reads {
		t.Fatalf("calls refused before the open read alina's keys %d times", r.reads-reads)
	}
	if !r.audited("rate_limited account:" + r.alina.acct.ID + " bucket:guest-total") {
		t.Fatalf("the refusals were not audited with the total named:\n%s", strings.Join(r.alina.log, "\n"))
	}
	// The control that must get through: the contact, from the address it used within the hour.
	if err := r.contactCalls(); err != nil {
		t.Fatalf("the contact from its known address, with the total spent: %v", err)
	}
	// A stranger from that same known address is let through to the open, and refused after it,
	// sealed: known addresses are for contacts, and strangers still spend the total.
	h := r.stranger(20)
	reads = r.reads
	if got, _ := r.post("127.0.0.1:50000", "", r.seal(h.Key, h.Chain, "chain", "request_contact", map[string]any{"card": h.Card("Stranger", "required")})); got != "sealed" || r.reads == reads {
		t.Fatalf("a stranger from the contact's known address: %s, %d key reads; want opened and refused, sealed", got, r.reads-reads)
	}
	// The known cost: the contact from an address it has not used is refused before the open.
	bk, err := identity.ToLib(r.bharat.kp())
	if err != nil {
		t.Fatal(err)
	}
	got, wait := r.post(proxy, "198.51.100.77", r.seal(bk, [][]byte{r.bharat.leaf(), r.bharat.rc}, "chain", "get_card", map[string]any{}))
	if got != "rate_limited" || wait < 1 {
		t.Fatalf("the contact from a new address during the flood: %s retry_after %d, want refused before the open", got, wait)
	}
	// An hour on the total has refilled, and a stranger is answered again.
	r.clock.advance(time.Hour + time.Minute)
	h = r.stranger(30)
	if got, _ := r.post(proxy, "203.0.113.30", r.seal(h.Key, h.Chain, "chain", "request_contact", map[string]any{"card": h.Card("Stranger", "required")})); got != "sealed" {
		t.Fatalf("a stranger an hour later: %s", got)
	}
}

func TestSmallFormsNamingLeavesNobodyPinnedDrainTheTotalAndAreThenRefusedBeforeTheOpen(t *testing.T) {
	r := newTotalRig(t)
	proxy := proxyAddr + ":40000"
	if err := r.contactCalls(); err != nil {
		t.Fatalf("the contact's first call: %v", err)
	}
	// Invented senders, the small form, each from an address of its own: opened, and answered
	// chain_required in the clear, and each spends a call of the total.
	for i := range r.total {
		h := r.stranger(i)
		if got, _ := r.post(proxy, fmt.Sprintf("203.0.113.%d", i+1), r.seal(h.Key, nil, "leaf", "get_card", map[string]any{})); got != "chain_required" {
			t.Fatalf("invented sender %d: %s", i, got)
		}
	}
	reads := r.reads
	h := r.stranger(50)
	if got, wait := r.post(proxy, "203.0.113.50", r.seal(h.Key, nil, "leaf", "get_card", map[string]any{})); got != "rate_limited" || wait < 1 || r.reads != reads {
		t.Fatalf("the next invented sender: %s retry_after %d, %d key reads; want refused before the open", got, wait, r.reads-reads)
	}
	if err := r.contactCalls(); err != nil {
		t.Fatalf("the contact from its known address: %v", err)
	}
}

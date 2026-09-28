package node

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	"github.com/pact-cloud/pact-gateway/internal/public"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

type env struct {
	root     *pactidentity.PrivateKey
	rootCert []byte
	t        testing.TB
	st       store.Store
	kr       *core.Keyring
	idm      *identity.Manager
	cfg      core.Config
	mu       sync.Mutex
	rows     []string
}

func newEnv(t testing.TB, slugs ...string) (*env, []store.Account) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(dir, "keyring.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, kr: kr, idm: &identity.Manager{Store: st, Keyring: kr}}
	e.cfg = core.Config{
		DataDir: dir, PublicBind: "127.0.0.1:0", PublicURL: "https://node.example",
		Mode: core.ModeDirect, Seal: core.SealOptional, ClientCert: core.ClientCertPreferred,
		LANConnections: true,
	}
	var accts []store.Account
	for _, slug := range slugs {
		a, err := e.idm.CreateAccount(ctx, slug, strings.ToUpper(slug), identity.AlgoP256)
		if err != nil {
			t.Fatal(err)
		}
		// And give it a leaf. An account with a key and no chain cannot be served
		// (PACT §2) — the node skips it as awaiting its wallet — so every account a
		// node test expects to answer has to have been to one.
		e.issueLeaf(a)
		a, _ = st.GetAccountByID(ctx, a.ID)
		accts = append(accts, a)
	}
	return e, accts
}

// peerFor is the 2.0 pin a test caller holds for an account this env serves, and
// the dialer that reaches it.
//
// A server is recognised by the chain it presents, validated to the ROOT pinned
// at the address DIALED (PACT §2, §14.2 rule 5) — and the address the leaf names
// is the configured public URL, never the loopback the test listener is on. So
// the caller dials the name and the resolver sends it to the listener, which is
// what DNS does for a real caller. Pinning the node's leaf KEY instead used to
// work; that was the key-pinned generation's rule, and it is gone.
func (e *env) peerFor(acct store.Account, base string) (outbound.Peer, func(context.Context, string, string) (net.Conn, error)) {
	e.t.Helper()
	chain, err := e.idm.Chain(context.Background(), acct.ID)
	if err != nil || len(chain) != 2 {
		e.t.Fatalf("peerFor: the account holds no chain: %v", err)
	}
	vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: time.Now()})
	if !vr.OK {
		e.t.Fatalf("peerFor: the node's own chain does not validate: rule %d", vr.Rule)
	}
	u, err := url.Parse(vr.Endpoint)
	if err != nil {
		e.t.Fatal(err)
	}
	listen := strings.TrimPrefix(base, "https://")
	named := u.Hostname() + ":443"
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == named {
			addr = listen
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return outbound.Peer{Endpoint: vr.Endpoint, Root: vr.RootFingerprint, Leaf: chain[0]}, dial
}

// callerChain plays another person's wallet: an independent root and a leaf over
// a fresh host key, presented as a TLS client certificate. Under 2.0 this is the
// ONLY thing that establishes a transport identity — a lone self-signed
// certificate names no root and so names nobody (PACT §2, §14.2).
func callerChain(t testing.TB, endpoint string) (tls.Certificate, string) {
	t.Helper()
	rootKey, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Caller", Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	host, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: "Caller", RootCN: "Caller", RootKey: rootKey, HostPub: host.Public, Endpoint: endpoint,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf, rc}, PrivateKey: host.Ed}, pactidentity.Fingerprint(rootKey.Public.SPKI)
}

// issueLeaf plays the person's wallet: a root for this account, and a leaf over the
// key the account already holds, for the endpoint the node advertises.
func (e *env) issueLeaf(a store.Account) {
	e.t.Helper()
	ctx := context.Background()
	if e.root == nil {
		key, err := pactidentity.GenerateKey("ed25519")
		if err != nil {
			e.t.Fatal(err)
		}
		rc, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Test Owner", Key: key, NotBefore: time.Now().Add(-24 * time.Hour)})
		if err != nil {
			e.t.Fatal(err)
		}
		e.root, e.rootCert = key, rc
	}
	now := time.Now()
	csr, err := e.idm.IssueCSR(ctx, a.ID, identity.PurposeSignup, identity.EndpointFor(e.cfg.PublicURL, a.Slug), now)
	if err != nil {
		e.t.Fatal(err)
	}
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: "Test Owner", RootKey: e.root, RootSPKIs: [][]byte{e.root.Public.SPKI},
		Now: now, PreviousNotBefore: csr.PreviousNotBefore, ValidDays: 365,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, e.rootCert}, now); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) options() Options {
	return Options{
		Config: e.cfg, Store: e.st, Keyring: e.kr, Landing: testLanding,
		Audit: func(a, r, o string) { e.mu.Lock(); e.rows = append(e.rows, a+" "+r+" "+o); e.mu.Unlock() },
	}
}

// start builds and starts a node on an ephemeral port, returning it and its base URL.
func (e *env) start(o Options) (*Node, string) {
	e.t.Helper()
	n, err := New(context.Background(), o)
	if err != nil {
		e.t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := n.Start(context.Background(), ln); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = n.Stop(context.Background()) })
	return n, "https://" + n.Addr()
}

// AC: SNI selects each account's own identity certificate, and a caller that
// sends no SNI still gets a usable one.
func TestSNISelectsPerAccountIdentityCertificates(t *testing.T) {
	e, accts := newEnv(t, "alice", "bob")
	n, base := e.start(e.options())

	for _, a := range accts {
		conn, err := tls.Dial("tcp", strings.TrimPrefix(base, "https://"), &tls.Config{
			ServerName: a.Slug, InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("dial %s: %v", a.Slug, err)
		}
		leaf := conn.ConnectionState().PeerCertificates[0]
		conn.Close()
		spki, _ := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		sum := sha256.Sum256(spki)
		if got := "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]); got != a.Fingerprint {
			t.Fatalf("SNI %s served fingerprint %s, want %s", a.Slug, got, a.Fingerprint)
		}
	}
	// no SNI at all (an IP dial): the first account's certificate, not a failure
	conn, err := tls.Dial("tcp", strings.TrimPrefix(base, "https://"), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("no-SNI dial: %v", err)
	}
	conn.Close()
	if got := n.Slugs(); len(got) != 2 || got[0] != "alice" {
		t.Fatalf("slugs: %v", got)
	}
}

// AC: routes resolve per SPEC §5.2 and unknown paths and accounts 404.
func TestRoutingAndNotFound(t *testing.T) {
	e, accts := newEnv(t, "alice", "bob")
	_, base := e.start(e.options())
	c := insecureClient()

	// the /mcp alias exists only on a single-account node
	if code := status(t, c, base+"/mcp"); code != http.StatusNotFound {
		t.Fatalf("/mcp on a two-account node: %d", code)
	}
	for _, path := range []string{"/a/nope/mcp", "/nothing", "/i/", "/relay/mcp"} { // /relay/mcp is gone: it must 404 like any other unknown path
		if code := status(t, c, base+path); code != http.StatusNotFound {
			t.Fatalf("%s: %d", path, code)
		}
	}
	// a real invite renders on the landing page
	cm := &contacts.Manager{Store: e.st}
	token, _, err := cm.CreateInvite(context.Background(), accts[0].ID, contacts.InviteOptions{MaxUses: 1, Preset: "friend"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(base + "/i/" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	// The page shows the signed card, so it shows the certificate the card carries. This used to
	// require the string "X-PACT-KEY" on the page — a test pinning the retired vocabulary in front
	// of a person, which is how "hash it to check it matches X-PACT-KEY" outlived the property.
	if res.StatusCode != 200 || !strings.Contains(string(b), "X-PACT-CERT") {
		t.Fatalf("landing page: %d %s", res.StatusCode, firstLine(string(b)))
	}
	if strings.Contains(string(b), "X-PACT-KEY") {
		t.Fatal("the landing page still speaks of X-PACT-KEY, which no card carries")
	}

	// single-account node: the alias works
	e2, _ := newEnv(t, "solo")
	_, base2 := e2.start(e2.options())
	if code := status(t, c, base2+"/mcp"); code == http.StatusNotFound {
		t.Fatal("/mcp alias missing on a single-account node")
	}
}

// AC: an edge-mode config yields seal=required + client_cert=off in the built
// surface — the knobs are derived, never trusted from the wire.
func TestEdgeModeKnobs(t *testing.T) {
	e, accts := newEnv(t, "alice")
	e.cfg.Mode, e.cfg.Seal, e.cfg.ClientCert = core.ModeEdge, core.SealRequired, core.ClientCertOff
	e.cfg.LANConnections = false
	o := e.options()
	o.Adapter = "cloudflare"
	n, base := e.start(o)

	// no CertificateRequest is sent at all under client_cert: off
	if got := n.TLSConfig().ClientAuth; got != tls.NoClientCert {
		t.Fatalf("edge listener still requests certificates: %v", got)
	}
	// A plaintext substantive call is refused BY THE NODE, before authorization, and the code is
	// `identity_required`: behind an edge no client certificate ever arrives, so an unsealed call
	// establishes nobody, and identity precedes sealing (§4.11, §5.3).
	//
	// This test used to build its peer with `Seal: "required"` and call `send_message`. A client
	// that reads "required" off a card refuses to send plaintext at all (`ErrSealRequired`), so
	// the refusal it asserted was the client's own, made before a byte left the process — true
	// of `outbound`, and saying nothing about the node's knobs, which is what the test is named
	// for. Here the caller believes the policy is "none", the pin is real (the node's chain, at
	// the address its leaf names) so the call arrives, and the tool is one a stranger's surface
	// HAS: `send_message` is not, and a stranger asking for it is told `blocked_or_unknown`
	// before any policy is consulted.
	kp, _ := identity.Generate(identity.AlgoP256)
	der, _ := identity.SelfSignedCert(kp, "peer")
	peer, dial := e.peerFor(accts[0], base)
	if peer.Seal == "required" {
		t.Fatal("the caller must believe plaintext is allowed, or the client refuses locally and the node is never asked")
	}
	client := &outbound.Client{Keypair: kp, Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}, DialContext: dial}
	res, err := client.CallTool(context.Background(), peer, "request_contact",
		map[string]any{"card": "BEGIN:VCARD\nEND:VCARD", "note": "unsealed"}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatalf("the call never reached the node, so its refusal is unobserved: %v", err)
	}
	if !res.IsError {
		t.Fatal("an unsealed substantive call was accepted under seal=required")
	}
	refusal := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			refusal += tc.Text
		}
	}
	if !strings.Contains(refusal, "identity_required") {
		t.Fatalf("the node refused an unsealed call with %q, want identity_required", refusal)
	}
}

// AC: Stop releases the port — a second node binds the same address.
func TestStopReleasesThePort(t *testing.T) {
	e, _ := newEnv(t, "alice")
	n, err := New(context.Background(), e.options())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := n.Start(context.Background(), ln); err != nil {
		t.Fatal(err)
	}
	if n.Addr() != addr {
		t.Fatalf("addr %s want %s", n.Addr(), addr)
	}
	if err := n.Start(context.Background(), nil); err == nil {
		t.Fatal("a second Start on a running node succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	again, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port still held after Stop: %v", err)
	}
	again.Close()
	// a node that cannot open an account key must fail at New, not at call time
	e2, accts := newEnv(t, "bob")
	other, _ := core.OpenKeyring(filepath.Join(t.TempDir(), "other.key"), func(string) (string, bool) { return "", false })
	o := e2.options()
	o.Keyring = other
	_, err = New(context.Background(), o)
	if err == nil {
		t.Fatalf("a node built with the wrong keyring for account %s", accts[0].Slug)
	}
	// The refusal cannot tell a wrong master key from a lost one, so it has to say both: what to
	// supply if it is the first, and that the identities survive — with the way through — if it is
	// the second. It used to say only "no account could be served", which under 2.0 reads as a
	// loss that has not happened: the identity is a root in a wallet.
	for _, want := range []string{"PACT_MASTER_KEY", "pact-gateway export", "pact-gateway import", "roots in wallets"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name both meanings and the way through; missing %q in: %v", want, err)
		}
	}
}

// One broken account among working ones does not stop the node, and until 2026-09-19 it did not
// show either: an audit row, and `serve` printing "serving". The node names it, with the reason.
func TestAnAccountWhoseKeyWillNotOpenIsNamedNotHidden(t *testing.T) {
	e, _ := newEnv(t, "alice")
	ctx := context.Background()
	other, err := core.OpenKeyring(filepath.Join(t.TempDir(), "other.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	// Sealed under a master key this node does not have.
	if _, err := (&identity.Manager{Store: e.st, Keyring: other}).CreateAccount(ctx, "carol", "CAROL", identity.AlgoP256); err != nil {
		t.Fatal(err)
	}
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatalf("one broken account took the node down: %v", err)
	}
	got := n.Unavailable()
	if len(got) != 1 || got["carol"] == "" {
		t.Fatalf("the broken account must be named with its reason: %v", got)
	}
	if _, ok := got["alice"]; ok {
		t.Fatal("a working account was reported as broken")
	}
}

// AC: the LAN guard refuses private-range sources when the flag is off, and
// audits every refusal.
// E13. This test used to assert the opposite — that a loopback call with the LAN
// flag off is refused — which is what the flag literally said and what made every
// edge-mode deployment unable to serve a request: the connector IS on loopback.
// The guard governs connections that bypass the carrier, and the carrier's own
// delivery is not one. Refusal of a genuine LAN source, and its audit event, are
// pinned in public.TestLANGuardServesTheCarriersOwnLoopbackDelivery, where the
// source address can be set; the guard's wiring into a real listener is covered
// by integrationtest/edge_test.go.
func TestLANGuardServesTheConnectorOnLoopback(t *testing.T) {
	e, _ := newEnv(t, "alice")
	e.cfg.LANConnections = false
	o := e.options()
	o.Adapter = "cloudflare" // an edge adapter: the flag is off and meaningful
	_, base := e.start(o)

	if code := status(t, insecureClient(), base+"/a/alice/mcp"); code == http.StatusForbidden {
		t.Fatalf("the node refused a request delivered over loopback, which is the only "+
			"way an edge connector delivers: %d", code)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rows {
		if strings.HasPrefix(r, "lan_refused ") {
			t.Fatalf("the carrier's own delivery was audited as a LAN refusal: %v", e.rows)
		}
	}
}

// E14. Every reverse tunnel produces exactly this shape: the connection arrives
// over loopback while the Host header carries the PUBLIC name. The MCP SDK turns
// on DNS-rebinding protection automatically for that combination
// (mcp/streamable.go:326), so every tunnelled MCP call was answered
// `Forbidden: invalid Host header` — in direct mode as much as edge, since the
// trigger is the socket, not the deployment mode.
//
// Disabling it on the PUBLIC surface is safe because that surface is always TLS
// (node.go serves it through tls.NewListener) and carries the node's own
// certificate: a rebinding page cannot obtain a certificate for the attacker's
// name, so the handshake fails before any Host header is read. The owner MCP,
// which is plain HTTP on loopback, keeps the protection.
func TestTunnelledCallIsNotRefusedAsDNSRebinding(t *testing.T) {
	e, _ := newEnv(t, "alice")
	o := e.options()
	o.Adapter = "frp"
	_, base := e.start(o)

	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"pact-test","version":"1"}}}`
	req, err := http.NewRequest("POST", base+"/a/alice/mcp", strings.NewReader(initialize))
	if err != nil {
		t.Fatal(err)
	}
	// dialled on loopback, addressed as the public name — a tunnelled request
	req.Host = "alice.example.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := insecureClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if strings.Contains(string(body), "invalid Host header") {
		t.Fatalf("a tunnelled MCP call was refused as DNS rebinding, so no tunnelled "+
			"deployment can serve MCP at all: %d %s", res.StatusCode, firstLine(string(body)))
	}
	if !strings.Contains(string(body), "protocolVersion") {
		t.Fatalf("the call did not complete an MCP initialize: %d %s",
			res.StatusCode, firstLine(string(body)))
	}
}

/* -------------------------------- helpers ------------------------------- */

func insecureClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

func status(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// AC (P8-01, defect #1): the account row is what the card advertises and the live
// cell is what the gate enforces — SetSeal must move them together. Persisting
// the RAW requested value lets a forced mode diverge: the cell holds `required`
// while the row says `optional`, and every card emitter that reads the row then
// advertises a policy the gate does not enforce.
func TestSetSealPersistsTheEffectiveValueNotTheRequestedOne(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "alice")
	e.cfg.Mode, e.cfg.Seal, e.cfg.ClientCert = core.ModeEdge, core.SealRequired, core.ClientCertOff
	e.cfg.LANConnections = false
	o := e.options()
	o.Adapter = "cloudflare"
	n, err := New(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	acct := accts[0]

	// edge mode forces sealing; asking for anything weaker cannot be honored
	if err := n.SetSeal(ctx, acct.ID, core.SealOptional); err != nil {
		t.Fatal(err)
	}

	if got := n.accounts[acct.ID].sealValue(); got != core.SealRequired {
		t.Fatalf("live cell = %s, want required", got)
	}
	row, err := e.st.GetAccountByID(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Seal != string(core.SealRequired) {
		t.Fatalf("account row = %s while the gate enforces required: every card built "+
			"from the row would advertise a policy the gate does not honor", row.Seal)
	}
	card, err := n.Card(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(card, "X-PACT-SEAL:required") {
		t.Fatalf("card disagrees with the gate:\n%s", card)
	}
}

// AC (P10-02): PACT §12's caps must actually be enforced on the shipped
// surface. They were implemented, tested as a library, and never installed — so
// `rate_limited` was a code no caller could ever receive. The budget counts
// CALLS: an earlier attempt limited HTTP requests, which a single MCP session
// exhausts before it asks for anything.
func TestGuestRateLimitIsEnforcedOnTheRealListener(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "alice")
	_, base := e.start(e.options())

	kp, _ := identity.Generate(identity.AlgoP256)
	der, _ := identity.SelfSignedCert(kp, "guest")
	peer, dial := e.peerFor(accts[0], base)
	client := &outbound.Client{Keypair: kp, DialContext: dial,
		Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}}

	// This caller presents a certificate that is no chain, so no root is proven and its
	// address alone pays: 60 calls an hour (PACT §12's source budget). Each of these is
	// refused on its merits — the token is nonsense — but it is still a call, and the 61st
	// must be refused for the budget instead.
	for i := 0; i < public.GuestSourceCallsPerHour+2; i++ {
		res, err := client.CallTool(ctx, peer, "redeem_invite",
			map[string]any{"token": "nope", "card": ""}, outbound.CallOptions{Plaintext: true})
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		text := ""
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*mcp.TextContent); ok {
				text = tc.Text
			}
		}
		if strings.Contains(text, "rate_limited") {
			if i < public.GuestSourceCallsPerHour {
				t.Fatalf("refused at call %d, before the budget was spent", i)
			}
			if !strings.Contains(text, "retry_after") {
				t.Fatalf("a rate_limited refusal carried no retry hint: %s", text)
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			for _, row := range e.rows {
				if strings.HasPrefix(row, "rate_limited ") {
					return
				}
			}
			t.Fatalf("the refusal was not audited: %v", e.rows)
		}
	}
	t.Fatalf("%d guest calls all served; the cap is not installed", public.GuestSourceCallsPerHour+2)
}

// AC (P10-03): SPEC §5.6 binds an MCP session to the identity that created it.
// The binder was written and tested and never wired, so a session id presented
// under a different identity kept the surface it was composed for.
// AC (P11-05): a session id created under one identity is refused when replayed
// under another, on the shipped handler, over real TLS.
//
// The library-level test below passed while the shipped surface had no check at
// all: the binding lived inside the SDK's getServer callback, which is invoked
// ONLY for a request carrying no session id. A caller who learned an id was
// served the surface that session was composed for — with no certificate of
// their own.
//
// This drives two DIFFERENT TLS identities through the real handler and asserts
// on the HTTP answer, never on the binder. Asserting on the binder is what made
// the first attempt at this test worthless: it bound the session itself, so it
// passed whether or not the node did.
func TestSessionIdCannotBeReplayedByAnotherIdentity(t *testing.T) {
	e, _ := newEnv(t, "alice")
	_, base := e.start(e.options())

	chain, _ := callerChain(t, "https://caller.example/a/caller/mcp")
	withCert := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{chain},
		},
	}}

	post := func(c *http.Client, sid, payload string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", base+"/a/alice/mcp", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"a","version":"1"}}}`

	// A caller WITH a certificate creates the session.
	res := post(withCert, "", initialize)
	sid := res.Header.Get("Mcp-Session-Id")
	res.Body.Close()
	if sid == "" {
		t.Fatalf("no session id was issued (status %d)", res.StatusCode)
	}

	// The same id, presented by a caller with NO certificate, must be refused.
	// This is the reported bypass verbatim.
	res2 := post(insecureClient(), sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	defer res2.Body.Close()
	if res2.StatusCode == http.StatusOK {
		t.Fatal("a session created under a client certificate was served to a caller presenting none")
	}

	// …and the identity that created it keeps working, so the guard refuses the
	// impostor rather than simply breaking sessions.
	res3 := post(withCert, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	defer res3.Body.Close()
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("the session's own creator was locked out: %d", res3.StatusCode)
	}
}

func TestSessionIsBoundToTheIdentityThatCreatedIt(t *testing.T) {
	e, _ := newEnv(t, "alice")
	n, _ := e.start(e.options())

	if !n.binder.Bind("sess-1", "sha256:alice") {
		t.Fatal("first use of a session id was refused")
	}
	if n.binder.Bind("sess-1", "sha256:mallory") {
		t.Fatal("a second identity reused another caller's session id")
	}
	if !n.binder.Bind("sess-1", "sha256:alice") {
		t.Fatal("the original identity lost its own session")
	}
	// an anonymous caller that later presents a certificate starts fresh
	if !n.binder.Bind("sess-2", "") {
		t.Fatal("anonymous session refused")
	}
	if n.binder.Bind("sess-2", "sha256:alice") {
		t.Fatal("a caller that gained an identity kept the anonymous session")
	}
	n.binder.Release("sess-2")
	if !n.binder.Bind("sess-2", "sha256:alice") {
		t.Fatal("a released session id could not be reused")
	}
}

// AC (P10-06c): behind a terminating ingress the node accepts only the ingress
// it paired with — and that certificate is a TRANSPORT check, never a caller
// identity (SPEC §10.1, §10.6).
//
// `NodePinningConfig` had no production caller and the pairing threw the
// ingress fingerprint away, so a terminate-mode node answered the onward leg
// from anyone who could reach it.
func TestTerminatingIngressIsPinnedOnTheOnwardLeg(t *testing.T) {
	ctx := context.Background()
	e, _ := newEnv(t, "alice")

	ing, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	other, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}

	o := e.options()
	o.IngressFingerprint = ing.Fingerprint
	n, err := New(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	tc := n.TLSConfig()
	if tc.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("the onward leg does not demand a certificate: %v", tc.ClientAuth)
	}
	if tc.VerifyConnection == nil {
		t.Fatal("the onward leg accepts any certificate")
	}
	if err := tc.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{PublicKey: ing.Signer.Public()}},
	}); err != nil {
		t.Fatalf("the paired ingress was refused: %v", err)
	}
	if err := tc.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{PublicKey: other.Signer.Public()}},
	}); err == nil {
		t.Fatal("an unpaired front door was accepted")
	}
	if err := tc.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("a connection with no certificate was accepted")
	}

	// The ingress certificate must NOT become the caller's identity. It is
	// checked at the handshake and stops there: caller identity in terminate
	// mode comes from the sealed envelope (§10.1), and recording the ingress as
	// the caller would fail §5.3's unified identity rule on every sealed call —
	// the transport identity could never equal the envelope signer — and would
	// bucket every caller's rate budget under the one edge.
	{
		srv := n.srv
		if srv.IgnoreClientCert == nil || !srv.IgnoreClientCert() {
			t.Fatal("the ingress certificate would be recorded as the caller's identity")
		}
		rec := httptest.NewRecorder()
		var got public.TransportFacts
		h := srv.Handler()
		_ = h
		probe := srv.WithFactsForTest(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = public.FactsFrom(r.Context())
		}))
		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: ing.Signer.Public()}}}
		probe.ServeHTTP(rec, req)
		if got.ClientCertFingerprint != "" || len(got.ClientCertSPKI) != 0 {
			t.Fatalf("the edge certificate leaked into caller identity: %q", got.ClientCertFingerprint)
		}
	}

	// Without a paired terminating ingress, nothing changes: requiring a
	// certificate on a direct listener would refuse every ordinary caller.
	plain, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}
	if plain.TLSConfig().ClientAuth == tls.RequireAnyClientCert {
		t.Fatal("a node with no ingress started demanding client certificates")
	}
}

// AC (P14-05a): an account created while the node is RUNNING must be servable
// immediately.
//
// The node only knew the accounts that existed when it started, so `account
// create` on a running node produced one the public listener could not serve:
// every TLS handshake for it failed with `tls: internal error` (alert 80) until a
// restart. The README quickstart tells a new owner to do exactly that sequence —
// `docker compose up`, then `account create` — so this was the ordinary path.
func TestAdoptAccountMakesANewAccountServableWithoutRestart(t *testing.T) {
	e, _ := newEnv(t, "alice")
	ctx := context.Background()
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}

	// A second account appears in the store after the node is up.
	acct, err := e.idm.CreateAccount(ctx, "late", "Late", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	e.issueLeaf(acct)
	acct, _ = e.st.GetAccountByID(ctx, acct.ID)

	// Before adoption the node cannot present a certificate for it.
	if _, err := n.certificate(&tls.ClientHelloInfo{ServerName: "late"}); err == nil {
		var served bool
		for _, s := range n.Slugs() {
			if s == "late" {
				served = true
			}
		}
		if served {
			t.Fatal("setup: the node already knew the account, so this proves nothing")
		}
	}

	if err := n.AdoptAccount(ctx, acct.ID); err != nil {
		t.Fatalf("AdoptAccount: %v", err)
	}

	cert, err := n.certificate(&tls.ClientHelloInfo{ServerName: "late"})
	if err != nil {
		t.Fatalf("no certificate for an adopted account — a handshake for it would fail "+
			"with tls: internal error until the node restarts: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("adopted account has an empty certificate")
	}
	var found bool
	for _, s := range n.Slugs() {
		if s == "late" {
			found = true
		}
	}
	if !found {
		t.Errorf("adopted account is not in the served slug list: %v", n.Slugs())
	}
}

// Adopting twice must be safe: it is also how a rotated key reaches the listener.
func TestAdoptAccountIsIdempotent(t *testing.T) {
	e, _ := newEnv(t, "alice")
	ctx := context.Background()
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}
	acct, err := e.idm.CreateAccount(ctx, "twice", "Twice", identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	e.issueLeaf(acct)
	acct, _ = e.st.GetAccountByID(ctx, acct.ID)
	for i := 0; i < 2; i++ {
		if err := n.AdoptAccount(ctx, acct.ID); err != nil {
			t.Fatalf("adopt #%d: %v", i+1, err)
		}
	}
	if _, err := n.certificate(&tls.ClientHelloInfo{ServerName: "twice"}); err != nil {
		t.Fatalf("re-adopting broke the account: %v", err)
	}
}

func TestAdoptAccountRefusesAnUnknownAccount(t *testing.T) {
	e, _ := newEnv(t, "alice")
	ctx := context.Background()
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.AdoptAccount(ctx, "no-such-account"); err == nil {
		t.Fatal("adopting an account that does not exist was accepted")
	}
}

// Edge mode FORCES client_cert off (SPEC §10.1): the edge terminates TLS, so the
// node never sees a client certificate and identity comes from the sealed
// envelope alone. The rate limiter read only the certificate, so behind
// Cloudflare, ngrok or a terminate-mode ingress EVERY contact was classified as
// an anonymous guest and budgeted per IP — and a tunnelled peer arrives from its
// edge's address, so all of them shared one bucket. Two contacts having a normal
// conversation exhausted the guest allowance (PACT §12: 10/hour) and everything
// after it was refused `rate_limited`.
//
// The owner found it the only way anyone could: by sending messages both ways at
// once and watching both nodes refuse.
func TestASealedContactIsNotBudgetedAsAGuest(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	ctx := context.Background()

	const peer = "sha256:the-contact"
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: peer, Status: "active",
		DisplayName: "Peer", Card: "BEGIN:VCARD...",
	}); err != nil {
		t.Fatal(err)
	}
	o := e.options()
	n, err := New(ctx, o)
	if err != nil {
		t.Fatal(err)
	}

	// What an edge delivers: no client certificate, an address shared by every
	// caller behind that edge, and identity only inside the envelope.
	edge := public.WithFacts(ctx, public.TransportFacts{RemoteIP: "203.0.113.7"})
	sealed := public.WithEnvelopeFacts(edge, &public.EnvelopeFacts{From: peer})

	key := n.classifyCtx(sealed, acct.ID, public.ChargeCaller)
	if key.Kind != public.KindContact {
		t.Fatalf("a sealed call from an active contact was budgeted as %q keyed on %q — "+
			"in edge mode that is every peer, sharing one per-IP bucket",
			key.Kind, key.IP)
	}
	if key.Fingerprint != peer || key.AccountID != acct.ID {
		t.Errorf("budget keyed on %q of %q, want the envelope's sender %q of %q", key.Fingerprint, key.AccountID, peer, acct.ID)
	}

	// A stranger who seals is still a guest, and still keeps the IP dimension.
	unknown := public.WithEnvelopeFacts(edge, &public.EnvelopeFacts{From: "sha256:nobody"})
	if k := n.classifyCtx(unknown, acct.ID, public.ChargeCaller); k.Kind != public.KindGuest || k.IP != "203.0.113.7" {
		t.Errorf("an unknown sealed caller was not treated as a guest: %+v", k)
	}
	// The contact at an address the owner has not approved, or at the pending tier, pays as a guest.
	if k := n.classifyCtx(sealed, acct.ID, public.ChargeGuest); k.Kind != public.KindGuest || k.Fingerprint != peer {
		t.Errorf("a guest charge of a pinned root was budgeted as %+v", k)
	}
	// A small form answered chain_required proves no root: the source alone pays.
	if k := n.classifyCtx(sealed, acct.ID, public.ChargeSource); k.Kind != public.KindSource || k.Fingerprint != "" || k.IP != "203.0.113.7" {
		t.Errorf("a source charge was budgeted as %+v", k)
	}
	// Budgets are the account's the call is addressed to: a contact of alice is a guest of any
	// other account on this node.
	if k := n.classifyCtx(sealed, "another-account", public.ChargeCaller); k.Kind != public.KindGuest || k.AccountID != "another-account" {
		t.Errorf("a contact of one account was budgeted as a contact of another: %+v", k)
	}
}

// PACT §13.4: at seal `none` the recipient does not accept envelopes, and the
// tool must not be listed — the card and the served surface tell one truth.
// The knob is live: SetSeal installs or removes the sealed group with no
// restart, the same way integration tools come and go.
func TestSetSealNoneRemovesSealedCallFromTheSurface(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	ctx := context.Background()
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}

	listed := func() bool {
		t.Helper()
		n.mu.RLock()
		a := n.accounts[acct.ID]
		n.mu.RUnlock()
		out, err := a.pool.Dispatch(ctx, acct.ID, "sha256:someone", public.Payload{Method: "tools/list"})
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		return strings.Contains(string(out), public.SealedToolName)
	}

	if !listed() {
		t.Fatal("sealed_call missing at the default policy")
	}
	if err := n.SetSeal(ctx, acct.ID, core.SealNone); err != nil {
		t.Fatal(err)
	}
	if listed() {
		t.Fatal("seal:none still lists sealed_call — the card and the surface disagree")
	}
	// And back: the group returns when the policy does.
	if err := n.SetSeal(ctx, acct.ID, core.SealRequired); err != nil {
		t.Fatal(err)
	}
	if !listed() {
		t.Fatal("sealed_call did not return with the policy")
	}
}

// What "every account failed" means is decided by the master key, not by a head count. Two nodes,
// each with one broken account and nobody served:
//
//   - beside an account that HAS a key and only awaits its leaf, the node starts. That key opened,
//     so the master key is the store's own; and refusing would take away the admin socket the
//     waiting account needs in order to ask for its certificate — which is what it did until
//     2026-09-19, when the serve-level test for the banner walked into it.
//   - beside an account with NO key, the node still refuses. Nothing opened, so nothing says this
//     is the right master key, and starting under a wrong one seals new secrets under it.
func TestOneBrokenAccountStopsTheNodeOnlyWhenNothingProvesTheMasterKey(t *testing.T) {
	ctx := context.Background()
	stranger := func(t *testing.T) *core.Keyring {
		t.Helper()
		kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "other.key"), func(string) (string, bool) { return "", false })
		if err != nil {
			t.Fatal(err)
		}
		return kr
	}

	t.Run("an awaiting account whose key opened proves it", func(t *testing.T) {
		e, _ := newEnv(t)
		if _, err := e.idm.CreateAccount(ctx, "alice", "ALICE", identity.AlgoP256); err != nil {
			t.Fatal(err)
		}
		if _, err := (&identity.Manager{Store: e.st, Keyring: stranger(t)}).CreateAccount(ctx, "carol", "CAROL", identity.AlgoP256); err != nil {
			t.Fatal(err)
		}
		n, err := New(ctx, e.options())
		if err != nil {
			t.Fatalf("the node refused to start, and with it went the socket alice needs to ask for her leaf: %v", err)
		}
		if got := n.AwaitingLeaf(); len(got) != 1 || got[0] != "alice" {
			t.Fatalf("awaiting: %v", got)
		}
		if got := n.Unavailable(); len(got) != 1 || got["carol"] == "" {
			t.Fatalf("unavailable: %v", got)
		}
	})

	t.Run("an account with no key proves nothing", func(t *testing.T) {
		e, _ := newEnv(t)
		if _, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "dave", DisplayName: "DAVE", Algo: "p256"}); err != nil {
			t.Fatal(err)
		}
		if _, err := (&identity.Manager{Store: e.st, Keyring: stranger(t)}).CreateAccount(ctx, "carol", "CAROL", identity.AlgoP256); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ctx, e.options()); err == nil {
			t.Fatal("a node started with nothing to show its master key is the store's own")
		}
	})
}

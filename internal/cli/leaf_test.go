package cli

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// issueLeafFor plays the person's wallet for a test account: a root, and a leaf
// over the key the account already holds, for the endpoint the node advertises.
//
// Every test here that expects a node to SERVE needs this. An account with a key
// and no chain cannot be served (PACT §2) — the node skips it as awaiting its
// wallet — so `CreateAccount` alone, which was enough while a 1.x account served
// under a self-signed certificate, no longer is.
func issueLeafFor(t *testing.T, idm *identity.Manager, a store.Account, publicURL string) store.Account {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	key, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pactidentity.BuildRoot(pactidentity.RootOpts{
		CN: a.DisplayName, Key: key, NotBefore: now.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := idm.IssueCSR(ctx, a.ID, identity.PurposeSignup, identity.EndpointFor(guardSafe(publicURL, a.Slug), a.Slug), now)
	if err != nil {
		t.Fatalf("issueLeafFor: the node would not ask for a leaf: %v", err)
	}
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: a.DisplayName, RootKey: key, RootSPKIs: [][]byte{key.Public.SPKI},
		Now: now, PreviousNotBefore: csr.PreviousNotBefore, ValidDays: 365,
	})
	if err != nil {
		t.Fatalf("issueLeafFor: the wallet refused the request: %v", err)
	}
	if _, err := idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, rootCert}, now); err != nil {
		t.Fatalf("issueLeafFor: the node refused the leaf: %v", err)
	}
	out, err := idm.Store.GetAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// configPublicURL reads the public URL a test wrote into its config, so the leaf a
// test account is issued names the SAME endpoint the node will advertise. Guessing
// one would leave the leaf naming an address the node does not answer at.
func configPublicURL(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return "https://node.example" // a test that wrote no config serves nothing over the wire
	}
	var cfg struct {
		PublicURL string `json:"public_url"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.PublicURL == "" {
		return "https://node.example"
	}
	return cfg.PublicURL
}

// testPeer is a contact's side: a person's root, a host key under it, and the
// chain and card that go with them.
//
// A peer used to be one self-signed certificate — the key WAS the identity — so a
// test could make one in two lines. A 2.0 peer is a root, a leaf naming the address
// it answers at, and a chain it presents; the tests here need all three, so they
// build them in one place.
type testPeer struct {
	// Fingerprint is the ROOT fingerprint: the identity a contact row pins (PACT §2).
	Fingerprint string
	Wallet      *testid.Wallet
	Host        *testid.Host
	Cert        tls.Certificate // leaf then root, as PACT §14.2 requires
	KP          *identity.Keypair
	Endpoint    string
}

func (p *testPeer) Card(fn string) string { return p.Host.Card(fn, "") }
func (p *testPeer) Root() string          { return p.Wallet.Fpr }

func newTestPeer(t testing.TB, cn, endpoint string) *testPeer {
	t.Helper()
	w := testid.NewWallet(t, cn)
	h := w.Issue(t, endpoint)
	var signer crypto.Signer
	switch {
	case h.Key.Ed != nil:
		signer = h.Key.Ed
	case h.Key.EC != nil:
		signer = h.Key.EC
	default:
		t.Fatal("newTestPeer: the host key does not sign")
	}
	return &testPeer{
		Fingerprint: w.Fpr, Wallet: w, Host: h, KP: &identity.Keypair{Signer: signer, Fingerprint: h.Kid},
		Cert:     tls.Certificate{Certificate: [][]byte{h.LeafDER, w.RootDER}, PrivateKey: signer},
		Endpoint: endpoint,
	}
}

// peerIdentity keeps the shape the tests here already use — a peer and the
// certificate it presents — but the peer is a 2.0 identity and its Fingerprint is
// the ROOT, which is what a contact row pins.
func peerIdentity(t *testing.T, cn string) (*testPeer, tls.Certificate) {
	t.Helper()
	p := newTestPeer(t, cn, "https://"+cn+".example/a/"+cn+"/mcp")
	return p, p.Cert
}

// mustSPKI is the peer's LEAF key: what a contact row records, and what an
// envelope is sealed to.
func mustSPKI(t *testing.T, p *testPeer) []byte {
	t.Helper()
	return p.Host.Key.Public.SPKI
}

// textOf is the text payload of a tool result, or "".
func textOf(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	tc, _ := res.Content[0].(*mcp.TextContent)
	if tc == nil {
		return ""
	}
	return tc.Text
}

// **`runServeCfg` went on 2026-09-18.** It wrote a config, seeded a store and started the real
// `serve`, for the two CLI delivery tests that drove one node's portal into another node's store.
// Those tests were retired with 1.x: a hermetic pair needs loopback addresses, and PACT §14.2
// rule 5 forbids a leaf from naming one, so a two-node exchange over real certificates cannot be
// stood up in-process without a dial seam `serve` does not have. `internal/integrationtest`'s
// `pairing_test.go` is where that exchange is proven, with a dial map joining two nodes that
// advertise public names.

// guardSafe returns a public URL a leaf may actually name. These tests bind to
// 127.0.0.1 because that is where they really listen, and they advertise that
// address — but a leaf MUST NOT name a loopback, link-local or private host
// (PACT §14.2 rule 5), so the certificate names a stable public-looking address
// instead. Nothing here checks the SAN against the bind: callers dial the real
// address and pin by fingerprint, which is what the guard exists to protect.
func guardSafe(publicURL, slug string) string {
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" {
		return "https://" + slug + ".pact.example"
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || pactidentity.IPIsPrivate(host) {
		return "https://" + slug + ".pact.example"
	}
	return publicURL
}

// selfSigned is a plain identity key and its self-signed certificate — NOT a PACT
// identity. The ingress role is pinned by its SPKI over mutually-pinned mTLS, not
// by a root, so it is the one place here that still wants exactly this.
func selfSigned(t *testing.T, cn string) (*identity.Keypair, tls.Certificate) {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, cn)
	if err != nil {
		t.Fatal(err)
	}
	return kp, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
}

// waitFor polls until cond holds or the budget runs out. It came from the delivery
// tests, which the address guard retired; the exposure tests still need it.
func waitFor(t *testing.T, budget time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// nodePeer is the 2.0 pin a caller holds for a node under test, and the dialer
// that reaches it.
//
// Under 2.0 a server is recognised two ways and no third: the chain it presents,
// validated to the ROOT the caller pinned at the address the caller dialed, or
// WebPKI for that hostname (PACT §2). A test that pins the node's LEAF key was
// relying on a branch that belonged to the key-pinned generation, deleted on
// 2026-09-18 — and while it stood, none of these tests exercised the rule a real
// caller meets.
//
// The address is the wrinkle. §14.2 rule 5 is byte-equality between the leaf's
// URI and the address dialed, and a mismatch is a refusal, never a warning; but
// the address guard refuses a loopback endpoint, so `guardSafe` gives the leaf a
// public-looking name while the listener is on 127.0.0.1. The caller therefore
// dials the name and a resolver sends it to the listener — which is what a real
// caller does through DNS.
func nodePeer(t *testing.T, dir string, acct store.Account, listen string) (outbound.Peer, func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	// Read the address out of the LEAF, not out of the config. They differ on
	// purpose: the address guard refuses a loopback endpoint, so a leaf issued for
	// a node listening on 127.0.0.1 names something public-looking instead, and
	// which name that is depends on what the test wrote before issuing.
	chain, err := (&identity.Manager{Store: openStoreAt(t, dir)}).Chain(context.Background(), acct.ID)
	if err != nil || len(chain) != 2 {
		t.Fatalf("nodePeer: the account holds no chain: %v", err)
	}
	vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: time.Now()})
	if !vr.OK {
		t.Fatalf("nodePeer: the node's own chain does not validate: rule %d", vr.Rule)
	}
	u, err := url.Parse(vr.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
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

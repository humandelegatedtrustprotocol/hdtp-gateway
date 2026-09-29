package node

// The phase-1 exit demonstration (pact-cloud/docs/superpowers/specs/
// 2026-09-14-pact-2.0-go-node-design.md §9): two Go nodes pair as 2.0
// identities through an invite, message both ways in both envelope forms,
// one renews (the other learns the leaf from the chain, and follows
// certificate_renewed once its old pin has expired), one moves to a new
// address with the other following under `auto`. Hermetic: every node is a
// whole in-process node behind an httptest listener, and a dial map stands in
// for DNS so leaves can name real hosts.

import (
	"context"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/limits/limitstest"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// demoClock is one clock for every node, so a renewal and an expiry can be
// walked through without waiting for them.
type demoClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *demoClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *demoClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// demoNet maps the hosts leaves name onto local listeners.
type demoNet struct {
	mu    sync.Mutex
	hosts map[string]string
}

func (d *demoNet) set(host, addr string) { d.mu.Lock(); d.hosts[host] = addr; d.mu.Unlock() }
func (d *demoNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	d.mu.Lock()
	target, ok := d.hosts[host]
	d.mu.Unlock()
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, target)
}

type demoNode struct {
	t    *testing.T
	st   store.Store
	idm  *identity.Manager
	n    *Node
	acct store.Account
	slug string
	host string
	dir  string // the node's data directory: its database is <dir>/<slug>.db
	root *pactidentity.PrivateKey
	rc   []byte // root certificate
	log  []string
	// hook, when set, sees each audit line as it is written, inside the handler that writes it.
	hookMu sync.Mutex
	hook   func(line string)
}

func (d *demoNode) onAudit(f func(line string)) { d.hookMu.Lock(); d.hook = f; d.hookMu.Unlock() }

func (d *demoNode) endpoint() string { return identity.EndpointFor("https://"+d.host, d.slug) }
func (d *demoNode) rootFpr() string  { return pactidentity.Fingerprint(d.root.Public().SPKI) }

// leaf is the current leaf; leafKey its key.
func (d *demoNode) leaf() []byte {
	chain, err := d.idm.Chain(context.Background(), d.acct.ID)
	if err != nil || len(chain) != 2 {
		d.t.Fatalf("%s: no chain: %v", d.slug, err)
	}
	return chain[0]
}
func (d *demoNode) leafSPKI() []byte {
	leaf, err := pactidentity.Parse(d.leaf())
	if err != nil {
		d.t.Fatal(err)
	}
	return leaf.SPKI
}
func (d *demoNode) kp() *identity.Keypair {
	d.n.mu.RLock()
	defer d.n.mu.RUnlock()
	return d.n.accounts[d.acct.ID].kp
}
func (d *demoNode) card() string {
	card, err := d.n.Card(context.Background(), d.acct.ID)
	if err != nil {
		d.t.Fatal(err)
	}
	return card
}
func (d *demoNode) contact(fpr string) store.Contact {
	c, err := d.st.GetContact(context.Background(), d.acct.ID, fpr)
	if err != nil {
		d.t.Fatalf("%s has no contact %s", d.slug, fpr)
	}
	return c
}

// issue runs the wallet's side of a CSR: the person's root signs it.
func (d *demoNode) issue(csr identity.CSRResult, days int, now time.Time) [][]byte {
	d.t.Helper()
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: d.acct.DisplayName, RootKey: d.root, RootSPKIs: [][]byte{d.root.Public().SPKI},
		Now: now, PreviousNotBefore: csr.PreviousNotBefore, ValidDays: days,
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return [][]byte{iss.DER, d.rc}
}

// install runs the CSR round trip for a purpose and reloads the live account.
func (d *demoNode) install(purpose, endpoint string, days int, now time.Time) identity.InstallResult {
	d.t.Helper()
	ctx := context.Background()
	csr, err := d.idm.IssueCSR(ctx, d.acct.ID, purpose, endpoint, now)
	if err != nil {
		d.t.Fatal(err)
	}
	res, err := d.idm.InstallLeaf(ctx, d.acct.ID, d.issue(csr, days, now), now)
	if err != nil {
		d.t.Fatal(err)
	}
	if d.n != nil {
		if err := d.n.AdoptAccount(ctx, d.acct.ID); err != nil {
			d.t.Fatal(err)
		}
	}
	d.acct, _ = d.st.GetAccountByID(ctx, d.acct.ID)
	return res
}

func startDemoNode(t *testing.T, clock *demoClock, dn *demoNet, slug, name string, leafDays int) *demoNode {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, slug+".db"))
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
	idm := &identity.Manager{Store: st, Keyring: kr}
	acct, err := idm.CreateAccount(ctx, slug, name, identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	d := &demoNode{t: t, st: st, idm: idm, acct: acct, slug: slug, host: slug + ".test", dir: dir}
	d.root, err = pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	if d.rc, err = pactidentity.BuildRoot(pactidentity.RootOpts{CN: name, Key: d.root, NotBefore: clock.now().Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	d.install(identity.PurposeSignup, d.endpoint(), leafDays, clock.now())

	cfg := core.Config{DataDir: dir, PublicURL: "https://" + d.host, Mode: core.ModeDirect, Seal: core.SealRequired, ClientCert: core.ClientCertPreferred, LANConnections: true}
	n, err := New(ctx, Options{Config: cfg, Store: st, Keyring: kr, Now: clock.now, DialContext: dn.dial, Landing: testLanding,
		Limits: limitstest.StartDefault(t).Client,
		Audit: func(action, resource, outcome string) {
			line := action + " " + resource + " → " + outcome
			d.log = append(d.log, line)
			d.hookMu.Lock()
			hook := d.hook
			d.hookMu.Unlock()
			if hook != nil {
				hook(line)
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	d.n = n
	srv := httptest.NewUnstartedServer(n.Handler())
	srv.TLS = n.srv.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dn.set(d.host, srv.Listener.Addr().String())
	return d
}

// pinPeer is the owner's side of accepting a 2.0 contact from its card and chain.
func (d *demoNode) pinPeer(peer *demoNode) {
	d.t.Helper()
	if _, err := d.st.InsertContact(context.Background(), store.Contact{
		AccountID: d.acct.ID, Fingerprint: peer.rootFpr(), SPKI: peer.leafSPKI(), Status: "active",
		Permissions: []string{"message.text"}, DisplayName: peer.acct.DisplayName, Card: peer.card(),
		Endpoint: peer.endpoint(), Leaf: peer.leaf(), PinnedAt: d.n.now().Unix(),
	}); err != nil {
		d.t.Fatal(err)
	}
}

func (d *demoNode) invite(auto bool) string {
	d.t.Helper()
	d.n.mu.RLock()
	cm := d.n.accounts[d.acct.ID].cm
	d.n.mu.RUnlock()
	token, _, err := cm.CreateInvite(context.Background(), d.acct.ID, contacts.InviteOptions{AutoAccept: auto, Permissions: []string{"message.text"}})
	if err != nil {
		d.t.Fatal(err)
	}
	return token
}

func (d *demoNode) send(to *demoNode, toFpr, msgID, text string) messaging.Result {
	d.t.Helper()
	res, err := d.n.SendMessage(context.Background(), d.acct.ID, toFpr, messaging.Input{MsgID: msgID, Text: text, Origin: messaging.OriginPortal})
	if err != nil {
		d.t.Fatalf("%s → %s: %v\n%s", d.slug, to.slug, err, strings.Join(to.log, "\n"))
	}
	if res.Status != "delivered" {
		d.t.Fatalf("%s → %s: %s", d.slug, to.slug, res.Status)
	}
	return res
}

func (d *demoNode) received(text string) bool {
	ctx := context.Background()
	threads, _ := d.st.ListThreadsByAccount(ctx, d.acct.ID)
	for _, th := range threads {
		msgs, _ := d.st.ListMessagesByThread(ctx, d.acct.ID, th.ID)
		for _, m := range msgs {
			if m.Direction == "in" && strings.Contains(m.Body, text) {
				return true
			}
		}
	}
	return false
}

func TestExitDemo(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)

	// --- pairing through an invite: Bharat redeems Alina's, as a 2.0 guest ---
	token := alina.invite(true)
	clientB, _ := bharat.n.OutboundClient(bharat.acct.ID)
	peerA := outbound.Peer{Endpoint: alina.endpoint(), Seal: "required", Root: alina.rootFpr(), Leaf: alina.leaf()}
	res, err := clientB.SealedCall(ctx, peerA, "redeem_invite", map[string]any{"token": token, "card": bharat.card()}, "redeem-b")
	if err != nil || res.IsError {
		t.Fatalf("redeem: %v %+v", err, res)
	}
	if c := alina.contact(bharat.rootFpr()); c.Status != "active" || len(c.Leaf) == 0 || c.Endpoint != bharat.endpoint() {
		t.Fatalf("alina must pin bharat by his root at his address: %+v", c)
	}
	bharat.pinPeer(alina)

	// --- messages both ways: the chain once, the fingerprint after ---
	bharat.send(alina, alina.rootFpr(), "b1", "hello alina")
	if !alina.received("hello alina") {
		t.Fatal("alina did not receive b1")
	}
	if c := bharat.contact(alina.rootFpr()); c.ChainSentKid != bharat.kp().Fingerprint {
		t.Fatalf("after the first call bharat's pin must record the chain sent: %q", c.ChainSentKid)
	}
	bharat.send(alina, alina.rootFpr(), "b2", "again, by fingerprint")
	if !alina.received("again, by fingerprint") {
		t.Fatal("alina did not receive b2 (small form)")
	}
	alina.send(bharat, bharat.rootFpr(), "a1", "hello bharat")
	if !bharat.received("hello bharat") {
		t.Fatal("bharat did not receive a1")
	}

	// --- Alina renews with a fresh key ---
	oldLeaf, oldKP := alina.leaf(), alina.kp()
	clock.advance(time.Hour)
	ren := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	if !ren.KeyChanged || ren.OldKid != oldKP.Fingerprint {
		t.Fatalf("renewal: %+v", ren)
	}
	// Bharat still seals to the old key, which Alina holds until it expires;
	// her answer carries the chain and his pin follows it (§2, §14.3).
	bharat.send(alina, alina.rootFpr(), "b3", "to the old key")
	if c := bharat.contact(alina.rootFpr()); string(c.Leaf) != string(alina.leaf()) || string(c.Leaf) == string(oldLeaf) {
		t.Fatal("bharat's pin must follow the leaf the answer carried")
	}
	alina.send(bharat, bharat.rootFpr(), "a3", "from the new key")
	if !bharat.received("from the new key") {
		t.Fatal("bharat did not receive a3")
	}
	// --- certificate_renewed: a stale pin past the old leaf's expiry ---
	oldParsed, _ := pactidentity.Parse(oldLeaf)
	if err := bharat.st.RepinContactAddress(ctx, bharat.acct.ID, alina.rootFpr(), alina.endpoint(), oldLeaf, oldParsed.SPKI, clock.now().Unix()); err != nil {
		t.Fatal(err)
	}
	clock.advance(31 * 24 * time.Hour) // the 30-day first leaf is now expired and former
	bharat.send(alina, alina.rootFpr(), "b4", "to a key you no longer hold")
	if !alina.received("to a key you no longer hold") {
		t.Fatal("alina did not receive b4 after certificate_renewed")
	}
	if c := bharat.contact(alina.rootFpr()); string(c.Leaf) != string(alina.leaf()) {
		t.Fatal("bharat must have followed certificate_renewed to the current leaf")
	}

	// --- Alina moves to a new address; Bharat follows under `auto` ---
	alina.n.SetPublicURL("https://alina-new.test")
	dn.set("alina-new.test", dn.hosts["alina.test"])
	newEndpoint := identity.EndpointFor("https://alina-new.test", alina.slug)
	mv := alina.install(identity.PurposeMove, newEndpoint, 365, clock.now())
	if mv.OldEndpoint != alina.endpoint() || mv.Endpoint != newEndpoint || !mv.Moved {
		t.Fatalf("move: %+v", mv)
	}
	alina.host = "alina-new.test"
	done, failed, err := alina.n.AnnounceMove(ctx, alina.acct.ID, mv.Kid)
	if err != nil || done != 1 || failed != 0 {
		t.Fatalf("move campaign: %v done=%d failed=%d", err, done, failed)
	}
	if c := bharat.contact(alina.rootFpr()); c.Endpoint != newEndpoint || string(c.Leaf) != string(alina.leaf()) {
		t.Fatalf("bharat must follow alina to the new address: %+v", c)
	}
	bharat.send(alina, alina.rootFpr(), "b5", "at the new address")
	if !alina.received("at the new address") {
		t.Fatal("alina did not receive b5 at her new address")
	}
	// The former address is remembered for the address-claim rule (§5).
	formers, _ := bharat.st.ListFormerEndpoints(ctx, bharat.acct.ID)
	if len(formers) != 1 || formers[0].Root != alina.rootFpr() {
		t.Fatalf("former endpoints: %+v", formers)
	}
}

func mustListLeaves(t *testing.T, d *demoNode) []store.Leaf {
	t.Helper()
	leaves, err := d.st.ListLeaves(context.Background(), d.acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}

package identity

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// wallet is the person's side of PACT §9 in a test: a root, and the ledger the
// monotonic notBefore rule needs.
type wallet struct {
	key  *pactidentity.PrivateKey
	root []byte
	fpr  string
}

func newWallet(t *testing.T, cn string) *wallet {
	t.Helper()
	key, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	root, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: cn, Key: key, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &wallet{key: key, root: root, fpr: pactidentity.Fingerprint(key.Public.SPKI)}
}

func (w *wallet) issue(t *testing.T, csr CSRResult, now time.Time, days int) [][]byte {
	t.Helper()
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: "Alina Rao", RootKey: w.key, RootSPKIs: [][]byte{w.key.Public.SPKI}, Now: now,
		PreviousNotBefore: csr.PreviousNotBefore, ValidDays: days,
	})
	if err != nil {
		t.Fatalf("wallet refused the request: %v", err)
	}
	return [][]byte{iss.DER, w.root}
}

func leafEnv(t *testing.T) (*Manager, store.Account) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "leaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	a, err := m.CreateAccount(context.Background(), "alina", "Alina Rao", AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return m, a
}

const endpointA = "https://agent.alina.example/a/alina/mcp"

// The whole round trip of PACT §9 for a 1.x account: a request carrying the
// existing key, the wallet's leaf, the install — and what it changes.
func TestLeafUpgradeThenRenewThenMove(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()

	csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Kid != a.Fingerprint || csr.PreviousNotBefore != nil {
		t.Fatalf("an upgrade certifies the existing key: %+v", csr)
	}
	if info := pactidentity.CSRCheck(csr.CSR, nil); !info.OK || info.Endpoint != endpointA {
		t.Fatalf("the request does not check out: %+v", info)
	}
	// A second request replaces the first: one pending leaf at a time.
	if _, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now); err != nil {
		t.Fatal(err)
	}
	leaves, err := m.Store.ListLeaves(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, l := range leaves {
		if l.State == LeafPending {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("two requests left %d pending leaves; one at a time is the rule", pending)
	}
	res, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.FirstInstall || res.KeyChanged || res.RootFingerprint != w.fpr || res.Kid != a.Fingerprint || res.Endpoint != endpointA {
		t.Fatalf("install: %+v", res)
	}
	acct, _ := m.Store.GetAccountByID(ctx, a.ID)
	if acct.Protocol != 2 || acct.RootFingerprint != w.fpr || acct.Fingerprint != a.Fingerprint {
		t.Fatalf("account after upgrade: %+v", acct)
	}
	chain, err := m.Chain(ctx, a.ID)
	if err != nil || len(chain) != 2 {
		t.Fatalf("chain: %v %d", err, len(chain))
	}
	if vr := pactidentity.ValidateChain(chain, pactidentity.ChainOpts{Now: now, ExpectedRoot: w.fpr, ExpectedEndpoint: endpointA}); !vr.OK {
		t.Fatalf("the installed chain does not validate: rule %d %s", vr.Rule, vr.Reason)
	}
	keys, err := m.ActiveLeafKeypairs(ctx, a.ID, now)
	if err != nil || len(keys) != 1 || !keys[0].Current || keys[0].KP.Protocol != 2 || keys[0].KP.Fingerprint != a.Fingerprint {
		t.Fatalf("active keys after upgrade: %v %+v", err, keys)
	}
	info, _ := m.Certificate(ctx, a.ID, now)
	if info.Protocol != 2 || info.RenewalDue || info.PendingCSR != "" || info.Kid != a.Fingerprint {
		t.Fatalf("certificate: %+v", info)
	}
	if info, _ := m.Certificate(ctx, a.ID, now.Add(340*24*time.Hour)); !info.RenewalDue {
		t.Fatal("renewal is due thirty days ahead")
	}

	// A renewal carries a fresh key; the old one is superseded and still served
	// until its notAfter; the account's key column follows.
	later := now.Add(300 * 24 * time.Hour)
	csr2, err := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, later)
	if err != nil {
		t.Fatal(err)
	}
	if csr2.Kid == a.Fingerprint || csr2.PreviousNotBefore == nil {
		t.Fatalf("a renewal must carry a fresh key and the previous notBefore: %+v", csr2)
	}
	res2, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr2, later, 365), later)
	if err != nil {
		t.Fatal(err)
	}
	if res2.FirstInstall || !res2.KeyChanged || res2.OldKid != a.Fingerprint || res2.OldKP == nil || res2.Kid != csr2.Kid {
		t.Fatalf("renewal install: %+v", res2)
	}
	keys, _ = m.ActiveLeafKeypairs(ctx, a.ID, later)
	if len(keys) != 2 || !keys[0].Current || keys[0].Kid != csr2.Kid || keys[1].Current || keys[1].Kid != a.Fingerprint {
		t.Fatalf("active keys after renewal: %+v", keys)
	}
	acct, _ = m.Store.GetAccountByID(ctx, a.ID)
	if acct.Fingerprint != csr2.Kid {
		t.Fatalf("the account's key column did not follow the leaf: %+v", acct)
	}
	// Past the old leaf's notAfter the superseded key is destroyed, its kid kept.
	keys, _ = m.ActiveLeafKeypairs(ctx, a.ID, now.Add(400*24*time.Hour))
	if len(keys) != 1 {
		t.Fatalf("expired superseded key still served: %+v", keys)
	}
	if former, _ := m.FormerKids(ctx, a.ID, now.Add(400*24*time.Hour)); len(former) != 1 || former[0] != a.Fingerprint {
		t.Fatalf("former kids: %v", former)
	}

	// A move names another endpoint; the leaf must name exactly it.
	elsewhere := "https://alina.pact.contact/alina/mcp"
	csr3, err := m.IssueCSR(ctx, a.ID, PurposeMove, elsewhere, later.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	res3, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr3, later.Add(time.Hour), 365), later.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res3.Endpoint != elsewhere || !res3.KeyChanged {
		t.Fatalf("move install: %+v", res3)
	}
	// Two keys are superseded by now — the 1.x key the upgrade retired and the
	// renewal's — and both are still inside their notAfter at this moment, so
	// both are held. (They used to be reported as one because a READ retired the
	// first; reads no longer write, and `RetireExpiredLeafKeys` does that.)
	if info, _ := m.Certificate(ctx, a.ID, later.Add(time.Hour)); info.Endpoint != elsewhere || len(info.Superseded) != 2 {
		t.Fatalf("certificate after move: %+v", info)
	}
	// Past both their windows they are former, and the key material goes.
	far := later.Add(400 * 24 * time.Hour)
	if info, _ := m.Certificate(ctx, a.ID, far); len(info.Superseded) != 0 || len(info.Former) != 2 {
		t.Fatalf("certificate past both windows: %+v", info)
	}
}

func TestInstallLeafRefusals(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w, other := newWallet(t, "Alina Rao"), newWallet(t, "Mallory")
	now := time.Now()

	if _, err := m.InstallLeaf(ctx, a.ID, nil, now); err == nil || !strings.Contains(err.Error(), "no certificate request is pending") {
		t.Fatalf("install without a request: %v", err)
	}
	if _, err := m.IssueCSR(ctx, a.ID, PurposeSignup, "http://agent.alina.example/mcp", now); err == nil {
		t.Fatal("a non-https endpoint was accepted")
	}
	if _, err := m.IssueCSR(ctx, a.ID, "wander", endpointA, now); err == nil {
		t.Fatal("an unknown purpose was accepted")
	}
	csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	// A leaf for another endpoint: rule 5.
	wrongEndpoint, _ := m.IssueCSR(ctx, a.ID, PurposeSignup, "https://elsewhere.example/mcp", now)
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, CSRResult{CSR: csr.CSR}, now, 365), now); err == nil || !strings.Contains(err.Error(), "rule 5") {
		t.Fatalf("a leaf naming another endpoint than the pending request: %v", err)
	}
	_ = wrongEndpoint
	// Back to the right request; a leaf carrying a key the request did not.
	csr, _ = m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	stray, _ := pactidentity.GenerateKey("ed25519")
	strayCSR, _ := pactidentity.CSRNew("Alina Rao", stray, endpointA, "")
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, CSRResult{CSR: strayCSR}, now, 365), now); err == nil || !strings.Contains(err.Error(), "not the requested") {
		t.Fatalf("a leaf carrying a stray key: %v", err)
	}
	// The good one.
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now); err != nil {
		t.Fatal(err)
	}
	// A chain to another root, once one is named: rule 2.
	csr2, _ := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, now.Add(time.Hour))
	if _, err := m.InstallLeaf(ctx, a.ID, other.issue(t, csr2, now.Add(time.Hour), 365), now.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "rule 2") {
		t.Fatalf("a chain to another root: %v", err)
	}
	// An older notBefore than the current leaf's: superseded, refused (§14.3).
	csr3, _ := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, now)
	old := CSRResult{CSR: csr3.CSR} // no previous notBefore: the wallet dates it an hour before now, earlier than the current leaf
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, old, now.Add(-48*time.Hour), 365), now); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("an older leaf: %v", err)
	}
	// Longer than 398 days: rule 4.
	csr4, _ := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, now.Add(2*time.Hour))
	if _, err := pactidentity.IssueFromCSR(csr4.CSR, pactidentity.IssueOpts{RootCN: "Alina Rao", RootKey: w.key, RootSPKIs: [][]byte{w.key.Public.SPKI}, Now: now, ValidDays: 400}); err == nil {
		t.Fatal("the wallet issued a 400-day leaf")
	}
}

// A first install that changes the key — a 1.x account asked for a renewal
// rather than an upgrade — retires the 1.x identity key like a superseded leaf.
// That key has no leaf of its own, and it must still be SERVED: 1.x contacts
// pinned it and reach us with it until they re-pin. It was inserted and then
// skipped by every reader, so nothing answered them.
func TestFirstInstallKeepsTheRetiringOneXKeyServed(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	oneX := a.Fingerprint

	csr, err := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Kid == oneX {
		t.Fatal("a renewal mints a fresh key; that is the case under test")
	}
	res, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.FirstInstall || !res.KeyChanged || res.OldKid != oneX || res.OldKP == nil {
		t.Fatalf("install: %+v", res)
	}

	keys, err := m.ActiveLeafKeypairs(ctx, a.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !keys[0].Current || keys[0].Kid != csr.Kid {
		t.Fatalf("the current leaf comes first: %d keys, first %+v", len(keys), keys[0])
	}
	old := keys[1]
	if old.Kid != oneX {
		t.Fatalf("the retiring 1.x key is served second, got %s", old.Kid)
	}
	if old.KP.Protocol != 1 || len(old.KP.Leaf) != 0 {
		t.Fatalf("it has no leaf of its own, so it stays a 1.x key: protocol %d, leaf %d bytes", old.KP.Protocol, len(old.KP.Leaf))
	}
	if old.KP.Fingerprint != oneX {
		t.Fatalf("it is the key 1.x contacts pinned: %s", old.KP.Fingerprint)
	}
	if !old.NotAfter.After(now) {
		t.Fatalf("kept for a year, not already expired: %s", old.NotAfter)
	}
	// And it is retired once its window closes, kid kept for certificate_renewed.
	later, err := m.ActiveLeafKeypairs(ctx, a.ID, old.NotAfter.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 1 {
		t.Fatalf("past its notAfter only the current leaf is served, got %d", len(later))
	}
	formers, err := m.FormerKids(ctx, a.ID, old.NotAfter.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range formers {
		if k == oneX {
			found = true
		}
	}
	if !found {
		t.Fatalf("its kid is kept as a former one (§14.4): %v", formers)
	}
	// The KEY is destroyed by the write path, not by a read.
	if err := m.RetireExpiredLeafKeys(ctx, a.ID, old.NotAfter.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	leaves2, err := m.Store.ListLeaves(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leaves2 {
		if l.Kid == oneX && (l.State != LeafFormer || len(l.KeySealed) != 0) {
			t.Fatalf("retiring leaves the kid and destroys the key: %+v", l)
		}
	}
}

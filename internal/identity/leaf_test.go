package identity

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	pactidentity "github.com/pact-cloud/pact-identity/go"
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
	return &wallet{key: key, root: root, fpr: pactidentity.Fingerprint(key.Public().SPKI)}
}

func (w *wallet) issue(t *testing.T, csr CSRResult, now time.Time, days int) [][]byte {
	t.Helper()
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{
		RootCN: "Alina Rao", RootKey: w.key, RootSPKIs: [][]byte{w.key.Public().SPKI}, Now: now,
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
	if !acct.HasRoot() || acct.RootFingerprint != w.fpr || acct.Fingerprint != a.Fingerprint {
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
	if err != nil || len(keys) != 1 || !keys[0].Current || !keys[0].KP.HasChain() || keys[0].KP.Fingerprint != a.Fingerprint {
		t.Fatalf("active keys after upgrade: %v %+v", err, keys)
	}
	info, _ := m.Certificate(ctx, a.ID, now)
	if !info.Certified || info.RenewalDue || info.PendingCSR != "" || info.Kid != a.Fingerprint {
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
	if res2.FirstInstall || !res2.KeyChanged || res2.OldKid != a.Fingerprint || len(res2.Retired) != 0 || res2.Kid != csr2.Kid || res2.Moved {
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
	if res3.Endpoint != elsewhere || !res3.KeyChanged || !res3.Moved {
		t.Fatalf("move install: %+v", res3)
	}
	// Two keys are superseded by now — the first leaf's and the renewal's — and both are
	// still inside their notAfter at this moment, so both are held. (They used to be reported as one because a READ retired the
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
	if _, err := pactidentity.IssueFromCSR(csr4.CSR, pactidentity.IssueOpts{RootCN: "Alina Rao", RootKey: w.key, RootSPKIs: [][]byte{w.key.Public().SPKI}, Now: now, ValidDays: 400}); err == nil {
		t.Fatal("the wallet issued a 400-day leaf")
	}
}

// A first leaf requested as a renewal mints a fresh key, so the key the account was created with
// is replaced without ever having been certified. PACT §14.4 keeps a superseded LEAF's key until
// its notAfter; this key was never a leaf. Before the first leaf an identity has no card and is
// not served, so no 2.0 sender can have sealed anything to it, and there is nobody to answer
// `certificate_renewed`.
//
// This test used to assert the opposite — `TestFirstInstallKeepsTheRetiringOneXKeyServed` — that
// the old key is kept for a year in a leafless ledger row and SERVED, because "1.x contacts
// pinned it and reach us with it until they re-pin". Those were the only callers who ever held it.
func TestAFirstLeafOverAFreshKeyRetiresNothing(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	created := a.Fingerprint

	csr, err := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Kid == created {
		t.Fatal("a renewal mints a fresh key; that is the case under test")
	}
	res, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.FirstInstall || !res.KeyChanged {
		t.Fatalf("install: %+v", res)
	}
	if res.OldKid != "" || len(res.Retired) != 0 {
		t.Fatalf("a first install supersedes no leaf, so it has no old key to report: %q", res.OldKid)
	}

	keys, err := m.ActiveLeafKeypairs(ctx, a.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].Current || keys[0].Kid != csr.Kid || !keys[0].KP.HasChain() {
		t.Fatalf("exactly one key is served, the certified one: %d keys", len(keys))
	}
	leaves, err := m.Store.ListLeaves(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leaves {
		if l.Kid == created {
			t.Fatalf("the never-certified key is still in the ledger as %q", l.State)
		}
		if len(l.Leaf) == 0 && l.State != LeafPending {
			t.Fatalf("a %s row with no leaf: nothing can be sealed to a key no card ever carried", l.State)
		}
	}
	// And the account holds the new key, not the old one: the overwrite is what destroyed it.
	got, err := m.Store.GetAccountByID(ctx, a.ID)
	if err != nil || got.Fingerprint != csr.Kid {
		t.Fatalf("the account names %s, want the certified key %s (%v)", got.Fingerprint, csr.Kid, err)
	}
}

// AC (2026-09-18): the FIRST leaf over an account that names a key it does not hold installs,
// and the host starts serving an identity it holds no key for.
//
// No leaf key travels between hosts (PACT §9), so an account can name a leaf kid issued
// elsewhere with nothing here to sign with. It asks its wallet for a move and installs what
// comes back. (An export of today's format arrives with no key named at all:
// TestAnImportedSlugHoldsOnlyItsRootUntilTheFirstChainInstalls.)
//
// It could not be done at all until 2026-09-18. `GetAccountSealedKey` reported an absent
// key as an error, so both branches written for it — the mint in `IssueCSR` and the
// "nothing to retire" in `InstallLeaf` — were unreachable, and the install failed on
// "read the key being retired".
func TestFirstLeafAfterADataOnlyImport(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "moved.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	w := newWallet(t, "Alina Rao")
	now := time.Now()

	// The imported row: the person's root, the PREVIOUS host's leaf kid as the
	// account's fingerprint, and no key material anywhere.
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: string(AlgoEd25519)})
	if err != nil {
		t.Fatal(err)
	}
	const elsewhere = "sha256:the-old-host-leaf"
	if err := st.SetAccountKey(ctx, a.ID, elsewhere, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountRoot(ctx, a.ID, w.fpr, w.root); err != nil {
		t.Fatal(err)
	}
	if sealed, serr := st.GetAccountSealedKey(ctx, a.ID); serr != nil || len(sealed) != 0 {
		t.Fatalf("the imported account must hold no key and read cleanly: %q %v", sealed, serr)
	}

	const here = "https://agent.newhost.example/a/alina/mcp"
	csr, err := m.IssueCSR(ctx, a.ID, PurposeMove, here, now)
	if err != nil {
		t.Fatalf("a moved identity could not ask for a leaf: %v", err)
	}
	if csr.Kid == elsewhere {
		t.Fatal("the request carries the key of the host it left")
	}
	res, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now)
	if err != nil {
		t.Fatalf("the first leaf after a move would not install: %v", err)
	}
	if res.Endpoint != here || res.RootFingerprint != w.fpr {
		t.Fatalf("installed under the wrong name or address: %+v", res)
	}
	// And it MOVED, which is what starts the campaign that tells its contacts (PACT §9). This was
	// worked out by the caller from the superseded leaf's endpoint, and an import has no
	// superseded leaf — so the one install that is a move by construction campaigned to nobody.
	if !res.Moved {
		t.Fatalf("an identity that arrived from another host with no ledger was not reported as moved: %+v", res)
	}
	// Nothing to retire: the account named a key it never held, so that kid must not
	// become a superseded leaf — the host would be promising `certificate_renewed`
	// answers it cannot seal (PACT §14.4).
	if res.OldKid != "" || len(res.Retired) != 0 {
		t.Fatalf("a key this host never had was retired: %+v", res)
	}
	leaves, err := st.ListLeaves(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leaves {
		if l.Kid == elsewhere {
			t.Fatalf("the previous host's leaf kid was kept as %s", l.State)
		}
	}
	// And it serves: the account's key column points at the new leaf, and the chain
	// it presents is leaf then root.
	got, err := st.GetAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != csr.Kid || !got.HasRoot() {
		t.Fatalf("the account still names the host it left: %+v", got)
	}
	keys, err := m.ActiveLeafKeypairs(ctx, a.ID, now)
	if err != nil || len(keys) == 0 || !keys[0].Current || keys[0].Kid != csr.Kid {
		t.Fatalf("no current leaf to serve under: %+v %v", keys, err)
	}
}

// The same account, asked for a `signup` instead: a host with no key of its own
// mints one rather than refusing. The leave note tells people to run `move`, so
// this is the second door into the same room — and it was shut for the same reason.
func TestSignupMintsAKeyWhenTheHostHasNone(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "moved-signup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: string(AlgoEd25519)})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountKey(ctx, a.ID, "sha256:the-old-host-leaf", nil); err != nil {
		t.Fatal(err)
	}
	csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, time.Now())
	if err != nil {
		t.Fatalf("signup on a host holding no key: %v", err)
	}
	if csr.Kid == "" || csr.Kid == "sha256:the-old-host-leaf" {
		t.Fatalf("signup did not mint a key of this host's own: %+v", csr)
	}
}

// Whether an install MOVED the identity when no current leaf says where it was, because the last
// one ran out: the ledger's last row is what this host knows about where the identity answered.
func TestAnInstallOverAFormerLedgerKnowsWhetherItMoved(t *testing.T) {
	const there = "https://agent.alina.example/a/alina/mcp"
	for _, c := range []struct {
		name, purpose, endpoint string
		moved                   bool
	}{
		{"the same address again — a renewal after the leaf ran out", PurposeRenew, there, false},
		{"another address — the node's address changed while it held no leaf", PurposeMove, "https://agent.newhost.example/a/alina/mcp", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, a := leafEnv(t)
			ctx := context.Background()
			w := newWallet(t, "Alina Rao")
			now := time.Now()
			csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, there, now)
			if err != nil {
				t.Fatal(err)
			}
			if first, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 365), now); err != nil || first.Moved {
				t.Fatalf("a signup is not a move: %+v %v", first, err)
			}
			// What expiry does to the ledger: the live row becomes former and both copies of the
			// key go. (An import leaves no ledger at all, and that case is the test above.)
			if _, err := m.RetireExpiredLeafKeys(ctx, a.ID, now.Add(400*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			later := now.Add(time.Hour)
			csr2, err := m.IssueCSR(ctx, a.ID, c.purpose, c.endpoint, later)
			if err != nil {
				t.Fatal(err)
			}
			res, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr2, later, 365), later)
			if err != nil {
				t.Fatal(err)
			}
			if res.Moved != c.moved || res.OldEndpoint != there {
				t.Fatalf("moved=%v (want %v), and the address it answered at before was %q (want %q)", res.Moved, c.moved, res.OldEndpoint, there)
			}
		})
	}
}

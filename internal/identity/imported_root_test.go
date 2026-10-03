package identity

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// An export carries its owner's root FINGERPRINT and not the root's certificate (HDTP §9.2: the
// certificate comes with the new leaf's chain). So a slug an import creates holds a name and
// nothing else: the root it expects, no certificate, no key, no ledger. This is what holds that
// name to its word: the first chain installed must be under that root, and only that chain fills
// in the certificate.
func TestAnImportedSlugHoldsOnlyItsRootUntilTheFirstChainInstalls(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "imported.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	owner, stranger := newWallet(t, "Alina Rao"), newWallet(t, "Somebody Else")
	now := time.Now()

	// What an import writes: the account, and the root it expects. Nothing more.
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: string(AlgoEd25519)})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountRoot(ctx, a.ID, owner.fpr, nil); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootFingerprint != owner.fpr || len(got.RootCert) != 0 {
		t.Fatalf("the imported slug should hold its root's fingerprint and no certificate: %q %d bytes", got.RootFingerprint, len(got.RootCert))
	}
	if sealed, serr := st.GetAccountSealedKey(ctx, a.ID); serr != nil || len(sealed) != 0 {
		t.Fatalf("the imported slug holds %d bytes of key (%v)", len(sealed), serr)
	}
	if leaves, lerr := st.ListLeaves(ctx, a.ID); lerr != nil || len(leaves) != 0 {
		t.Fatalf("the imported slug holds a ledger: %+v %v", leaves, lerr)
	}
	// It has no chain to present until a leaf is installed.
	if chain, cerr := m.Chain(ctx, a.ID); cerr == nil || chain != nil {
		t.Fatalf("an imported slug with no leaf presented a chain: %d members, %v", len(chain), cerr)
	}

	const here = "https://agent.newhost.example/a/alina/mcp"
	csr, err := m.IssueCSR(ctx, a.ID, PurposeMove, here, now)
	if err != nil {
		t.Fatalf("the imported slug could not ask for a leaf: %v", err)
	}
	// A chain under any other root is refused, and changes nothing.
	if _, err := m.InstallLeaf(ctx, a.ID, stranger.issue(t, csr, now, 365), now); err == nil || !strings.Contains(err.Error(), "chain refused") {
		t.Fatalf("a chain under another root installed on a slug that expects %s: %v", owner.fpr, err)
	}
	if got, _ := st.GetAccountByID(ctx, a.ID); got.RootFingerprint != owner.fpr || len(got.RootCert) != 0 {
		t.Fatalf("a refused chain changed the account: %q %d bytes", got.RootFingerprint, len(got.RootCert))
	}
	// The owner's chain installs, and brings the root's certificate with it.
	res, err := m.InstallLeaf(ctx, a.ID, owner.issue(t, csr, now, 365), now)
	if err != nil {
		t.Fatalf("the owner's chain did not install: %v", err)
	}
	if res.RootFingerprint != owner.fpr || !res.Moved {
		t.Fatalf("the first leaf on the imported slug: %+v", res)
	}
	got, err = st.GetAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RootCert, owner.root) {
		t.Fatal("the install did not fill in the root's certificate from the chain")
	}
	chain, err := m.Chain(ctx, a.ID)
	if err != nil || len(chain) != 2 || !bytes.Equal(chain[1], owner.root) {
		t.Fatalf("the installed slug does not present leaf then root: %d members, %v", len(chain), err)
	}
}

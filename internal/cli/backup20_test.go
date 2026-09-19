package cli

// Backups (PACT §9). A bundle is the node's DATA: accounts, contacts, the ledger of leaves it has
// held. It is never a credential — no leaf key is in one, from this node or to it — so a restore
// anywhere ends at the same place: the identity's name is here, and the wallet certifies this
// host afresh. What differs between a same-node restore and another host's archive is the master
// key, which unseals saved settings and integration credentials and is refused from a stranger.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// idNode is a data directory with its own config and its own master key.
type idNode struct {
	dir, cfg string
}

func newIDNode(t *testing.T, name string) idNode {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.json")
	body := `{"data_dir":"` + dir + `","internal_bind":"127.0.0.1:0","public_bind":"127.0.0.1:0"}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"migrate", "--config", cfg}, "test", io.Discard, io.Discard); code != 0 {
		t.Fatalf("migrate %s: %d", name, code)
	}
	return idNode{dir: dir, cfg: cfg}
}

// testWallet is the person's side: a root, held by the test the way a wallet holds it.
type testWallet struct {
	key  *pactidentity.PrivateKey
	cert []byte
}

func newTestWallet(t *testing.T, cn string) *testWallet {
	t.Helper()
	key, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: cn, Key: key, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &testWallet{key: key, cert: cert}
}

func (w *testWallet) fingerprint() string { return pactidentity.Fingerprint(w.key.Public.SPKI) }

// certifyUnder has the node ask for a leaf and the wallet issue it. `at` orders the leaves: a
// second leaf for one identity must be newer than the first (PACT §14.3).
func (w *testWallet) certifyUnder(t *testing.T, n idNode, slug, purpose, endpoint string, at time.Time) identity.InstallResult {
	t.Helper()
	st := openStoreAt(t, n.dir)
	defer st.Close()
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, n.dir)}
	ctx := context.Background()
	a, err := st.GetAccountBySlug(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := idm.IssueCSR(ctx, a.ID, purpose, endpoint, at)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{RootCN: a.DisplayName, RootKey: w.key, RootSPKIs: [][]byte{w.key.Public.SPKI}, Now: at, ValidDays: 200})
	if err != nil {
		t.Fatal(err)
	}
	res, err := idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, w.cert}, at)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// certify runs the wallet's side of a signup for an account on a node, under a root made for it.
func certify(t *testing.T, n idNode, slug, endpoint string) (rootFpr string) {
	t.Helper()
	w := newTestWallet(t, slug)
	w.certifyUnder(t, n, slug, identity.PurposeSignup, endpoint, time.Now())
	return w.fingerprint()
}

// `backup identity` and `backup restore-identity` are gone, and this is the test that they stay
// gone. They sealed one account's leaf key under a passphrase, "portable to a different node" —
// the one thing a leaf key must never be: it is the root's trust in THIS host, for one address,
// until one date, and a second host holding it speaks as the first. A node that moves asks the
// wallet for a leaf of its own.
//
// The refusal has to land before anything is touched: no data directory made, no lock taken.
func TestThereIsNoIdentityExport(t *testing.T) {
	for _, sub := range []string{"identity", "restore-identity"} {
		dir := filepath.Join(t.TempDir(), "never-made")
		cfg := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(cfg, []byte(`{"data_dir":"`+dir+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errb := run(t, "backup", sub, "-config", cfg)
		if code != 2 || !strings.Contains(errb, "backup <create|restore>") {
			t.Fatalf("backup %s: code=%d out=%q err=%q", sub, code, out, errb)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Fatalf("backup %s made the data directory before refusing", sub)
		}
	}
}

func TestRestoreRefusesAnotherHostsKeysUnlessDataOnly(t *testing.T) {
	src := newIDNode(t, "src")
	dst := newIDNode(t, "dst")
	st := openStoreAt(t, src.dir)
	kr := openKeyringAt(t, src.dir)
	if _, err := (&identity.Manager{Store: st, Keyring: kr}).CreateAccount(t.Context(), "alice", "Alice", identity.AlgoEd25519); err != nil {
		t.Fatal(err)
	}
	st.Close()
	certify(t, src, "alice", "https://agent.alice.example/mcp")
	archive := filepath.Join(src.dir, "node.tar.gz")
	if code, _, errb := run(t, "backup", "create", "-config", src.cfg, "-out", archive); code != 0 {
		t.Fatalf("create: %s", errb)
	}
	// The destination is another host: its own keyring already exists.
	_ = openKeyringAt(t, dst.dir)
	dstKeyBefore, _ := os.ReadFile(filepath.Join(dst.dir, "keyring.key"))

	if code, _, errb := run(t, "backup", "restore", "-config", dst.cfg, "-from", archive, "-yes"); code == 0 || !strings.Contains(errb, "another node") {
		t.Fatalf("a foreign archive's keys must be refused: %d %s", code, errb)
	}
	if code, out, errb := run(t, "backup", "restore", "-config", dst.cfg, "-from", archive, "-yes", "-data-only"); code != 0 || !strings.Contains(out, "keys were not imported") {
		t.Fatalf("data-only restore: %d %s %s", code, out, errb)
	}
	if after, _ := os.ReadFile(filepath.Join(dst.dir, "keyring.key")); string(after) != string(dstKeyBefore) {
		t.Fatal("the destination's own master key must be untouched")
	}
	dstStore := openStoreAt(t, dst.dir)
	defer dstStore.Close()
	a, err := dstStore.GetAccountBySlug(t.Context(), "alice")
	if err != nil {
		t.Fatalf("the account's data must be here: %v", err)
	}
	if sealed, _ := dstStore.GetAccountSealedKey(t.Context(), a.ID); len(sealed) != 0 {
		t.Fatal("the other host's account key must not come along")
	}
	for _, l := range mustLeaves(t, dstStore, a.ID) {
		if len(l.KeySealed) != 0 || l.State != identity.LeafFormer {
			t.Fatalf("a leaf key must not come along; the row stays as former: %+v", l)
		}
	}
}

func TestRestoreOnAFreshNodeTreatsAnArchiveAsForeign(t *testing.T) {
	// A fresh machine has no keyring to compare with, and the manifest's id is
	// the former host's to write — neither is proof the archive is this node's.
	// So a fresh node refuses the keys too, unless the operator says it is
	// their own node's archive (-same-node) or takes the data alone.
	src := newIDNode(t, "src")
	st := openStoreAt(t, src.dir)
	kr := openKeyringAt(t, src.dir)
	if _, err := (&identity.Manager{Store: st, Keyring: kr}).CreateAccount(t.Context(), "alice", "Alice", identity.AlgoEd25519); err != nil {
		t.Fatal(err)
	}
	st.Close()
	certify(t, src, "alice", "https://agent.alice.example/mcp")
	archive := filepath.Join(src.dir, "node.tar.gz")
	if code, _, errb := run(t, "backup", "create", "-config", src.cfg, "-out", archive); code != 0 {
		t.Fatalf("create: %s", errb)
	}
	srcKey, _ := os.ReadFile(filepath.Join(src.dir, "keyring.key"))

	fresh := newIDNode(t, "fresh") // no keyring.key yet
	if _, err := os.Stat(filepath.Join(fresh.dir, "keyring.key")); err == nil {
		t.Fatal("the fresh node must start without a keyring")
	}
	if code, _, errb := run(t, "backup", "restore", "-config", fresh.cfg, "-from", archive, "-yes"); code == 0 || !strings.Contains(errb, "another node") {
		t.Fatalf("a fresh node must not take an archive's keys on faith: %d %s", code, errb)
	}
	if _, err := os.Stat(filepath.Join(fresh.dir, "keyring.key")); err == nil {
		t.Fatal("the refusal must land before the master key does")
	}
	if code, out, errb := run(t, "backup", "restore", "-config", fresh.cfg, "-from", archive, "-yes", "-data-only"); code != 0 || !strings.Contains(out, "keys were not imported") {
		t.Fatalf("data-only on a fresh node: %d %s %s", code, out, errb)
	}
	if _, err := os.Stat(filepath.Join(fresh.dir, "keyring.key")); err == nil {
		t.Fatal("data-only must not bring the master key")
	}

	own := newIDNode(t, "own") // the operator's own node, restored onto a fresh machine
	if code, _, errb := run(t, "backup", "restore", "-config", own.cfg, "-from", archive, "-yes", "-same-node"); code != 0 {
		t.Fatalf("same-node restore: %d %s", code, errb)
	}
	if got, _ := os.ReadFile(filepath.Join(own.dir, "keyring.key")); string(got) != string(srcKey) {
		t.Fatal("same-node must bring the master key as it was")
	}
	ownStore := openStoreAt(t, own.dir)
	defer ownStore.Close()
	a, err := ownStore.GetAccountBySlug(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	// The master key comes back; the leaf's key does not, and could not — no bundle carries one.
	// This asserted the opposite ("same-node must bring the account's sealed key") when a backup
	// was a copy of everything. A leaf is this host's credential for one address until one date,
	// so a restored node keeps the identity's NAME and asks the wallet to certify it again.
	if sealed, _ := ownStore.GetAccountSealedKey(t.Context(), a.ID); len(sealed) != 0 {
		t.Fatalf("a restore brought back %d bytes of leaf key: a leaf's key never travels", len(sealed))
	}
	if !a.HasRoot() {
		t.Fatal("the identity lost its root in the restore: the name must survive even though the key does not")
	}
}

func mustLeaves(t *testing.T, st store.Store, accountID string) []store.Leaf {
	t.Helper()
	leaves, err := st.ListLeaves(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}

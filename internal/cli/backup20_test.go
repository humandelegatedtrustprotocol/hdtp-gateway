package cli

// PACT 2.0 backups (PACT §9): `backup identity` of a 2.0 account moves the
// LEAF and its key to another node, never the root; `backup restore` of an
// archive made by another host refuses its key material unless asked for the
// data alone, and then strips every key.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// upgradeTo20 runs the wallet's side of a signup for an account on a node.
func upgradeTo20(t *testing.T, n idNode, slug, endpoint string) (rootFpr string) {
	t.Helper()
	st := openStoreAt(t, n.dir)
	defer st.Close()
	kr := openKeyringAt(t, n.dir)
	idm := &identity.Manager{Store: st, Keyring: kr}
	ctx := context.Background()
	a, err := st.GetAccountBySlug(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, _ := pactidentity.GenerateKey("ed25519")
	rootCert, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: a.DisplayName, Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := idm.IssueCSR(ctx, a.ID, identity.PurposeSignup, endpoint, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{RootCN: a.DisplayName, RootKey: rootKey, RootSPKIs: [][]byte{rootKey.Public.SPKI}, Now: time.Now(), ValidDays: 200})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, rootCert}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return pactidentity.Fingerprint(rootKey.Public.SPKI)
}

func TestIdentityBackupMovesA20LeafToAnotherNode(t *testing.T) {
	src := newIDNode(t, "src")
	dst := newIDNode(t, "dst")
	pass := passphraseFile(t, src.dir, "a passphrase worth using")
	st := openStoreAt(t, src.dir)
	kr := openKeyringAt(t, src.dir)
	if _, err := (&identity.Manager{Store: st, Keyring: kr}).CreateAccount(t.Context(), "alice", "Alice", identity.AlgoEd25519); err != nil {
		t.Fatal(err)
	}
	st.Close()
	rootFpr := upgradeTo20(t, src, "alice", "https://agent.alice.example/mcp")

	out := filepath.Join(src.dir, "alice.identity.json")
	var stdout, stderr strings.Builder
	if code := Run([]string{"backup", "identity", "--config", src.cfg, "-slug", "alice", "-out", out, "-passphrase-file", pass}, "test", &stdout, &stderr); code != 0 {
		t.Fatalf("export: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PACT 2.0 leaf under root "+rootFpr) {
		t.Fatalf("the export must say what it is: %s", stdout.String())
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), `"pact_identity_backup": 2`) || !strings.Contains(string(raw), `"root_fingerprint": "`+rootFpr) {
		t.Fatalf("not a version-2 document: %s", raw)
	}

	dstPass := passphraseFile(t, dst.dir, "a passphrase worth using")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"backup", "restore-identity", "--config", dst.cfg, "-from", out, "-passphrase-file", dstPass}, "test", &stdout, &stderr); code != 0 {
		t.Fatalf("restore: %d %s", code, stderr.String())
	}
	dstStore := openStoreAt(t, dst.dir)
	defer dstStore.Close()
	got, err := dstStore.GetAccountBySlug(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != 2 || got.RootFingerprint != rootFpr || len(got.RootCert) == 0 {
		t.Fatalf("the restored account must be the same 2.0 identity: %+v", got)
	}
	leaves, _ := dstStore.ListLeaves(t.Context(), got.ID)
	if len(leaves) != 1 || leaves[0].State != identity.LeafCurrent || leaves[0].Kid != got.Fingerprint || leaves[0].Endpoint != "https://agent.alice.example/mcp" {
		t.Fatalf("the leaf must be current on the new node: %+v", leaves)
	}
	dstKR := openKeyringAt(t, dst.dir)
	keys, err := (&identity.Manager{Store: dstStore, Keyring: dstKR}).ActiveLeafKeypairs(t.Context(), got.ID, time.Now())
	if err != nil || len(keys) != 1 || !keys[0].Current || keys[0].KP.Fingerprint != got.Fingerprint {
		t.Fatalf("the leaf key must open under the destination's keyring: %v %+v", err, keys)
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
	upgradeTo20(t, src, "alice", "https://agent.alice.example/mcp")
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

func mustLeaves(t *testing.T, st store.Store, accountID string) []store.Leaf {
	t.Helper()
	leaves, err := st.ListLeaves(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}

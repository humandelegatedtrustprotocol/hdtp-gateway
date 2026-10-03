package cli

// Helpers the identity-level tests of this package share: a node's data directory, a wallet that
// holds a root the way a person's does, and the ledger of leaves read back.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
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
	key  *hdtpidentity.PrivateKey
	cert []byte
}

func newTestWallet(t *testing.T, cn string) *testWallet {
	t.Helper()
	key, err := hdtpidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := hdtpidentity.BuildRoot(hdtpidentity.RootOpts{CN: cn, Key: key, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &testWallet{key: key, cert: cert}
}

func (w *testWallet) fingerprint() string { return hdtpidentity.Fingerprint(w.key.Public().SPKI) }

// certifyUnder has the node ask for a leaf and the wallet issue it. `at` orders the leaves: a
// second leaf for one identity must be newer than the first (HDTP §14.3).
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
	iss, err := hdtpidentity.IssueFromCSR(csr.CSR, hdtpidentity.IssueOpts{RootCN: a.DisplayName, RootKey: w.key, RootSPKIs: [][]byte{w.key.Public().SPKI}, Now: at, ValidDays: 200})
	if err != nil {
		t.Fatal(err)
	}
	res, err := idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, w.cert}, at)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func mustLeaves(t *testing.T, st store.Store, accountID string) []store.Leaf {
	t.Helper()
	leaves, err := st.ListLeaves(context.Background(), accountID)
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}

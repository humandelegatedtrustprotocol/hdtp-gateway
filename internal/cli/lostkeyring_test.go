package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/identity"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// The recovery table in docs/operations.md says a lost master key costs a node its leaves and not
// the identity: the root is in the wallet, so the wallet can certify the same host again. That row
// used to read "all identities are gone", which was true when the key in the store WAS the
// identity. This is the row, run: the master key is replaced with a stranger's, the old leaf key
// will never unseal again, and a renewal under the same root still installs and still opens.
func TestALostMasterKeyCostsALeafNotTheIdentity(t *testing.T) {
	n := newIDNode(t, "node")
	ctx := context.Background()
	st := openStoreAt(t, n.dir)
	idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, n.dir)}
	a, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "https://agent.alice.example/mcp"
	rootKey, _ := pactidentity.GenerateKey("ed25519")
	rootCert, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Alice", Key: rootKey, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(m *identity.Manager, purpose string, at time.Time) identity.InstallResult {
		t.Helper()
		csr, err := m.IssueCSR(ctx, a.ID, purpose, endpoint, at)
		if err != nil {
			t.Fatalf("%s request: %v", purpose, err)
		}
		iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{RootCN: "Alice", RootKey: rootKey, RootSPKIs: [][]byte{rootKey.Public().SPKI}, Now: at, ValidDays: 200})
		if err != nil {
			t.Fatal(err)
		}
		res, err := m.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, rootCert}, at)
		if err != nil {
			t.Fatalf("%s install: %v", purpose, err)
		}
		return res
	}
	now := time.Now()
	first := issue(idm, identity.PurposeSignup, now)
	if len(first.Retired) != 0 {
		t.Fatalf("an ordinary install retired something: %v", first.Retired)
	}

	// The master key is gone; the node makes itself another on its next start.
	if err := os.Remove(filepath.Join(n.dir, "keyring.key")); err != nil {
		t.Fatal(err)
	}
	after := &identity.Manager{Store: st, Keyring: openKeyringAt(t, n.dir)}
	if _, err := after.ActiveLeafKeypairs(ctx, a.ID, now); err == nil {
		t.Fatal("the old leaf key opened under a master key that never sealed it")
	}

	renewed := issue(after, identity.PurposeRenew, now.Add(time.Minute))
	// The outgoing leaf's key cannot be served, so it is not kept as if it could: it is retired,
	// and the install says so, because key material was destroyed.
	if len(renewed.Retired) != 1 || renewed.Retired[0] != first.Kid {
		t.Fatalf("the unopenable key must be retired and reported: %v (the outgoing kid is %s)", renewed.Retired, first.Kid)
	}
	for _, l := range mustLeaves(t, st, a.ID) {
		if l.Kid == first.Kid && (l.State != identity.LeafFormer || len(l.KeySealed) != 0) {
			t.Fatalf("the outgoing leaf must be former and keyless, so its kid is still answered certificate_renewed: state=%q key=%d bytes", l.State, len(l.KeySealed))
		}
	}

	got, err := st.GetAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootFingerprint != pactidentity.Fingerprint(rootKey.Public().SPKI) {
		t.Fatalf("the identity changed: root %s", got.RootFingerprint)
	}
	keys, err := after.ActiveLeafKeypairs(ctx, a.ID, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("after the renewal the node must serve again, and it cannot list its keys: %v", err)
	}
	if len(keys) == 0 || !keys[0].Current {
		t.Fatalf("no current leaf key after the renewal: %+v", keys)
	}
}

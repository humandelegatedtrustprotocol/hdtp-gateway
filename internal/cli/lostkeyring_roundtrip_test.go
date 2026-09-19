package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// The recovery the node's own refusal names, run as the operator would run it. With the master key
// gone for good and every account's key sealed under it, `serve` refuses to start — so there is no
// admin socket, and `account csr`, which is how a renewal begins, cannot be reached. The library
// can recover (TestALostMasterKeyCostsALeafNotTheIdentity); an operator could not, and the recovery
// table said they could.
//
// The way through needs no new command: a node that has lost its master key is, to its own data,
// another host. It takes its data and none of its keys.
func TestALostMasterKeyIsRecoveredByTreatingTheNodesDataAsAnotherHosts(t *testing.T) {
	n := newIDNode(t, "node")
	ctx := context.Background()
	st := openStoreAt(t, n.dir)
	if _, err := (&identity.Manager{Store: st, Keyring: openKeyringAt(t, n.dir)}).CreateAccount(ctx, "alice", "Alice", identity.AlgoEd25519); err != nil {
		t.Fatal(err)
	}
	st.Close()
	const endpoint = "https://agent.alice.example/mcp"
	wallet := newTestWallet(t, "Alice")
	now := time.Now()
	wallet.certifyUnder(t, n, "alice", identity.PurposeSignup, endpoint, now)
	rootFpr := wallet.fingerprint()
	if err := os.Remove(filepath.Join(n.dir, "keyring.key")); err != nil {
		t.Fatal(err)
	}

	// With the master key in the bundle this cannot work — there is none to put there — and the
	// command has to say so rather than write a bundle that claims one.
	archive := filepath.Join(n.dir, "data.tar.gz")
	if code, _, errb := run(t, "backup", "create", "-config", n.cfg, "-out", archive, "-without-master-key"); code != 0 {
		t.Fatalf("create without the master key: %s", errb)
	}
	if code, out, errb := run(t, "backup", "restore", "-config", n.cfg, "-from", archive, "-yes", "-data-only"); code != 0 || !strings.Contains(out, "keys were not imported") {
		t.Fatalf("data-only restore over itself: code=%d out=%q err=%q", code, out, errb)
	}

	got := openStoreAt(t, n.dir)
	a, err := got.GetAccountBySlug(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasRoot() || a.RootFingerprint != rootFpr {
		t.Fatalf("the identity must survive: root %q, want %q", a.RootFingerprint, rootFpr)
	}
	// No key left that a master key this node does not have would be asked to open: that is what
	// turns "no account could be served" into "awaiting a leaf", which `serve` starts with.
	if sealed, _ := got.GetAccountSealedKey(ctx, a.ID); len(sealed) != 0 {
		t.Fatalf("an unopenable key survived the round trip: %d bytes", len(sealed))
	}
	for _, l := range mustLeaves(t, got, a.ID) {
		if len(l.KeySealed) != 0 || l.State != identity.LeafFormer {
			t.Fatalf("a live leaf row survived: %+v", l)
		}
	}
	got.Close()
	// And the SAME wallet certifies this host again, under a master key made fresh. A different
	// root would be refused, rightly: that would be another person taking the name.
	res := wallet.certifyUnder(t, n, "alice", identity.PurposeRenew, endpoint, now.Add(time.Minute))
	if res.RootFingerprint != rootFpr || len(res.Retired) != 0 {
		t.Fatalf("the renewal after recovery: root %q (want %q), retired %v (want none: the round trip left no key to retire)", res.RootFingerprint, rootFpr, res.Retired)
	}
	after := openStoreAt(t, n.dir)
	keys, err := (&identity.Manager{Store: after, Keyring: openKeyringAt(t, n.dir)}).ActiveLeafKeypairs(ctx, a.ID, now.Add(2*time.Minute))
	if err != nil || len(keys) != 1 || !keys[0].Current {
		t.Fatalf("the node must hold one current leaf key it can open: %v %+v", err, keys)
	}
}

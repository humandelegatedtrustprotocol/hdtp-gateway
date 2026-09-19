package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core"
)

// "Until one date" has to be true of the KEY, not only of the certificate. A leaf that runs out
// under a running node used to go on being presented — to peers who refuse it — and its key went
// on being held, because an account once built was served until the process ended, and the only
// retirement there was looked at superseded leaves and ran when an account was adopted.
func TestALeafThatRunsOutStopsBeingServedAndLosesItsKey(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 30)

	served := func() bool {
		for _, s := range bharat.n.Slugs() {
			if s == "bharat" {
				return true
			}
		}
		return false
	}
	if !served() {
		t.Fatal("the account must be served while its leaf is good")
	}

	// A sweep inside the window changes nothing: this runs every hour on a healthy node.
	clock.advance(29 * 24 * time.Hour)
	bharat.n.RetireExpiredLeaves(ctx)
	if !served() {
		t.Fatal("a sweep took down an account whose leaf is still good")
	}

	clock.advance(2 * 24 * time.Hour)
	bharat.n.RetireExpiredLeaves(ctx)

	if served() {
		t.Fatal("the node is still serving an account whose leaf has run out")
	}
	if got := bharat.n.AwaitingLeaf(); len(got) != 1 || got[0] != "bharat" {
		t.Fatalf("the account must be reported as awaiting a leaf: %v", got)
	}
	if sealed, _ := bharat.st.GetAccountSealedKey(ctx, bharat.acct.ID); len(sealed) != 0 {
		t.Fatalf("the account still holds %d bytes of an expired leaf's key", len(sealed))
	}
	for _, l := range mustListLeaves(t, bharat) {
		if len(l.KeySealed) != 0 {
			t.Fatalf("the ledger still holds an expired leaf's key: state=%q kid=%s", l.State, l.Kid)
		}
	}
	// Key material was destroyed, so the chain says so — with why.
	said := false
	for _, row := range bharat.log {
		if strings.HasPrefix(row, "account_leaf_key_retired ") && strings.Contains(row, "reason:expired") && strings.HasSuffix(row, "→ ok") {
			said = true
		}
	}
	if !said {
		t.Fatalf("nothing on the audit chain says a key was destroyed:\n%s", strings.Join(bharat.log, "\n"))
	}

	// And a node that was DOWN when the leaf ran out boots the account as what it is: awaiting a
	// leaf. It used to boot it as broken — "is 2.0 but holds no current leaf" — and, being the only
	// account, that refused the whole node.
	bharat2 := startDemoNode(t, clock, dn, "carol", "Carol", 30)
	clock.advance(31 * 24 * time.Hour)
	again, err := New(ctx, Options{
		Config: core.Config{DataDir: t.TempDir(), PublicURL: "https://" + bharat2.host, Mode: core.ModeDirect, Seal: core.SealRequired, ClientCert: core.ClientCertPreferred, LANConnections: true},
		Store:  bharat2.st, Keyring: bharat2.idm.Keyring, Now: clock.now,
	})
	if err != nil {
		t.Fatalf("a node whose only leaf ran out while it was down must still start: %v", err)
	}
	if got := again.AwaitingLeaf(); len(got) != 1 || got[0] != "carol" {
		t.Fatalf("awaiting at boot: %v", got)
	}
	if got := again.Unavailable(); len(got) != 0 {
		t.Fatalf("an account that needs a renewal was reported as broken: %v", got)
	}
	if sealed, _ := bharat2.st.GetAccountSealedKey(ctx, bharat2.acct.ID); len(sealed) != 0 {
		t.Fatal("boot left an expired leaf's key in the account row")
	}
}

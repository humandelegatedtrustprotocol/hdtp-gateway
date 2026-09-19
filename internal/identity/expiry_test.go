package identity

import (
	"context"
	"testing"
	"time"
)

// A leaf is the root's trust in this host until one date. Past the date every verifier refuses the
// leaf (PACT §14.2 rule 4), so its key can do nothing legitimate, and holding it is exposure with
// no use. The retirement used to cover `superseded` leaves only: the key of a leaf that simply ran
// out, because nobody renewed it, stayed for good — in its ledger row and again in the account's.
func TestAnExpiredCurrentLeafLosesItsKeyInBothPlaces(t *testing.T) {
	m, a := leafEnv(t)
	ctx := context.Background()
	w := newWallet(t, "Alina Rao")
	now := time.Now()
	csr, err := m.IssueCSR(ctx, a.ID, PurposeSignup, endpointA, now)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr, now, 30), now)
	if err != nil {
		t.Fatal(err)
	}

	// Inside its window nothing is touched — the sweep runs hourly on a healthy node.
	if got, err := m.RetireExpiredLeafKeys(ctx, a.ID, now.Add(29*24*time.Hour)); err != nil || len(got) != 0 {
		t.Fatalf("a leaf inside its window was retired: %v %v", got, err)
	}
	if sealed, _ := m.Store.GetAccountSealedKey(ctx, a.ID); len(sealed) == 0 {
		t.Fatal("a live leaf's key was destroyed")
	}

	past := res.NotAfter.Add(time.Second)
	// Between the date and the next sweep — up to an hour on a running node — the key is still in
	// the store, and it must already be useless: the read path every inbound envelope takes does
	// not list it. It did, for a current leaf; only superseded ones were checked against the date.
	if keys, err := m.ActiveLeafKeypairs(ctx, a.ID, past); err != nil || len(keys) != 0 {
		t.Fatalf("an expired leaf's key is still offered for opening envelopes: %v %+v", err, keys)
	}
	if sealed, _ := m.Store.GetAccountSealedKey(ctx, a.ID); len(sealed) == 0 {
		t.Fatal("a read destroyed the key: that is the sweep's job, and reads must not write")
	}
	got, err := m.RetireExpiredLeafKeys(ctx, a.ID, past)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kid != res.Kid || !got[0].Current {
		t.Fatalf("the expired current leaf must be reported, as current: %+v", got)
	}
	// Both copies. The account row holds the same key the ledger row does.
	if sealed, _ := m.Store.GetAccountSealedKey(ctx, a.ID); len(sealed) != 0 {
		t.Fatalf("the account still holds %d bytes of an expired leaf's key", len(sealed))
	}
	leaves, _ := m.Store.ListLeaves(ctx, a.ID)
	if len(leaves) != 1 || leaves[0].State != LeafFormer || len(leaves[0].KeySealed) != 0 {
		t.Fatalf("the ledger row must stay, former and keyless: %+v", leaves)
	}
	// What stays: the name. The root, and the fingerprint every pin and audit row uses.
	acct, _ := m.Store.GetAccountByID(ctx, a.ID)
	if !acct.HasRoot() || acct.Fingerprint != res.Kid {
		t.Fatalf("the identity must survive its leaf: %+v", acct)
	}
	// And the kid is still answered for (§14.4), which needs the row and not the key.
	if former, _ := m.FormerKids(ctx, a.ID, past); len(former) != 1 || former[0] != res.Kid {
		t.Fatalf("former kids: %v", former)
	}
	// Idempotent: a second pass finds nothing left to do.
	if again, err := m.RetireExpiredLeafKeys(ctx, a.ID, past); err != nil || len(again) != 0 {
		t.Fatalf("a second pass retired something: %v %v", again, err)
	}

	// A renewal after expiry loses nothing by any of this: it never wanted the old key.
	csr2, err := m.IssueCSR(ctx, a.ID, PurposeRenew, endpointA, past)
	if err != nil {
		t.Fatalf("renew after expiry: %v", err)
	}
	if _, err := m.InstallLeaf(ctx, a.ID, w.issue(t, csr2, past, 30), past); err != nil {
		t.Fatalf("install after expiry: %v", err)
	}
	keys, err := m.ActiveLeafKeypairs(ctx, a.ID, past)
	if err != nil || len(keys) != 1 || !keys[0].Current || keys[0].Kid != csr2.Kid {
		t.Fatalf("after the renewal: %v %+v", err, keys)
	}
}

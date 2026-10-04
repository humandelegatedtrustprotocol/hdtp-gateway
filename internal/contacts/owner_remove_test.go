package contacts

import (
	"bytes"
	"context"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// HDTP §5.3 "After a removal": the receiver keeps the removed root for 30 days, whoever ended the
// relationship. The peer's own `remove_contact` (RemoveContact) left a tombstone; the owner's
// removal did not, so a root the owner removed came straight back in under `accept_new_hosts =
// auto` with a newer leaf. The cloud tombstones both (batondeck src/identity/identity.ts).
func TestTheOwnersRemovalLeavesATombstone(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := Owner{Manager: e.m}
	for _, status := range []string{"active", "pending_in", "pending_out", "blocked"} {
		g, card, spki := guest(t, "Removed"+status)
		if _, err := e.st.InsertContact(ctx, store.Contact{
			AccountID: e.account, Fingerprint: g.Fingerprint, SPKI: spki, Status: status,
			Card: card, Endpoint: g.Host.Endpoint, Leaf: g.Host.LeafDER, PinnedAt: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := o.Remove(ctx, e.account, g.Fingerprint); err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if _, err := e.st.GetContact(ctx, e.account, g.Fingerprint); err == nil {
			t.Fatalf("%s: the row is still there", status)
		}
		var found bool
		ts, err := e.st.ListTombstones(ctx, e.account)
		if err != nil {
			t.Fatal(err)
		}
		for _, tb := range ts {
			if tb.Root == g.Fingerprint {
				found = bytes.Equal(tb.Leaf, g.Host.LeafDER) && tb.At == e.clock.Unix()
			}
		}
		if !found {
			t.Fatalf("%s: the owner's removal left no tombstone with the removed leaf: %+v", status, ts)
		}
	}
	// The control: a row that never held a leaf has nothing a return could be compared with, and
	// leaves nothing behind.
	g, card, spki := guest(t, "Leafless")
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: g.Fingerprint, SPKI: spki, Status: "pending_out", Card: card}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Remove(ctx, e.account, g.Fingerprint); err != nil {
		t.Fatal(err)
	}
	ts, _ := e.st.ListTombstones(ctx, e.account)
	for _, tb := range ts {
		if tb.Root == g.Fingerprint {
			t.Fatal("a leafless row was tombstoned")
		}
	}
	// And a root this account does not hold is refused, writing nothing.
	before := len(ts)
	if _, err := o.Remove(ctx, e.account, "sha256:nobody"); err == nil {
		t.Fatal("removing a root nobody holds was accepted")
	}
	if ts, _ := e.st.ListTombstones(ctx, e.account); len(ts) != before {
		t.Fatal("a refused removal wrote a tombstone")
	}
}

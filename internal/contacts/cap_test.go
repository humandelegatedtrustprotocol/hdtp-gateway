package contacts

// The contact cap (limit.contacts) at every door that adds a contact: approve, unblock, a peer's
// auto-accept redemption, approving a contact at a new address. The owner's own adds (redeeming a
// link, sending a request) are held in internal/cli, and an import in internal/portable. What counts
// is active and pending_out; pending_in and blocked do not; nothing held is ever revoked.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// capped is an env whose accounts may hold two contacts, holding them.
func capped(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.m.ContactCap = func() int { return 2 }
	ctx := context.Background()
	for i, st := range []string{"active", "pending_out", "pending_in", "blocked"} {
		if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: fmt.Sprintf("sha256:held-%d", i), Status: st}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestWhatCountsAgainstTheCap(t *testing.T) {
	e := capped(t)
	ctx := context.Background()
	held, err := e.st.CountHeldContacts(ctx, e.account)
	if err != nil || held != 2 {
		t.Fatalf("held %d (%v): active and pending_out count, pending_in and blocked do not", held, err)
	}
	if err := e.m.Room(ctx, e.st, e.account); !errors.Is(err, ErrContactCap) {
		t.Fatalf("two held under a cap of two: %v, want the cap refusal", err)
	}
	e.m.ContactCap = func() int { return 3 }
	if err := e.m.Room(ctx, e.st, e.account); err != nil {
		t.Fatalf("room for one more was refused: %v", err)
	}
	e.m.ContactCap = nil
	if e.m.Cap() != 500 {
		t.Fatalf("an unset cap is %d, want the default 500", e.m.Cap())
	}
}

func TestApproveAndUnblockAreHeldToTheCap(t *testing.T) {
	e := capped(t)
	ctx := context.Background()
	o := Owner{Manager: e.m}
	if _, err := o.Approve(ctx, e.account, "sha256:held-2", ""); !errors.Is(err, ErrContactCap) {
		t.Fatalf("approve at the cap: %v", err)
	}
	if c, _ := e.st.GetContact(ctx, e.account, "sha256:held-2"); c.Status != "pending_in" {
		t.Fatalf("a refused approval moved the request to %s", c.Status)
	}
	// An ever-active contact that is blocked comes back active: one more, refused at the cap.
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: "sha256:was-friend", Status: "pending_in"}); err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{"active", "blocked"} { // ever active, then blocked
		if err := e.st.UpdateContactStatus(ctx, e.account, "sha256:was-friend", st); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.Unblock(ctx, e.account, "sha256:was-friend"); !errors.Is(err, ErrContactCap) {
		t.Fatalf("unblock at the cap: %v", err)
	}
	if c, _ := e.st.GetContact(ctx, e.account, "sha256:was-friend"); c.Status != "blocked" {
		t.Fatalf("a refused unblock moved the row to %s", c.Status)
	}
	// Forgetting a declined request adds nothing and is never refused.
	if d, err := o.Unblock(ctx, e.account, "sha256:held-3"); err != nil || d.Status != "none" {
		t.Fatalf("forgetting a declined request at the cap: %+v %v", d, err)
	}
	// Room made, the same approval works.
	if _, err := o.Remove(ctx, e.account, "sha256:held-0"); err != nil {
		t.Fatal(err)
	}
	if d, err := o.Approve(ctx, e.account, "sha256:held-2", ""); err != nil || d.Status != "active" {
		t.Fatalf("approve after making room: %+v %v", d, err)
	}
}

// A peer redeeming an auto-accept link at the cap is refused before the use is spent, and a caller
// this account blocked hears exactly what a stranger hears (HDTP §12). A link that only asks still
// lands a request: pending_in does not count.
func TestARedemptionAtTheCapSpendsNothing(t *testing.T) {
	e := capped(t)
	ctx := context.Background()
	token, _, err := e.m.CreateInvite(ctx, e.account, InviteOptions{AutoAccept: true})
	if err != nil {
		t.Fatal(err)
	}
	stranger, card, _ := guest(t, "Stranger")
	_, strangerErr := e.m.RedeemAs(ctx, e.account, token, card, stranger.proof())
	if !errors.Is(strangerErr, ErrContactCap) {
		t.Fatalf("an auto-accept redemption at the cap: %v", strangerErr)
	}
	if _, err := e.st.GetContact(ctx, e.account, stranger.Fingerprint); err == nil {
		t.Fatal("a refused redemption wrote a row")
	}
	if invs, _ := e.st.ListInvites(ctx, e.account); len(invs) != 1 || invs[0].Uses != 0 {
		t.Fatalf("a refused redemption spent a use: %+v", invs)
	}
	blocked, bcard, _ := guest(t, "Blocked")
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: blocked.Fingerprint, Status: "blocked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.RedeemAs(ctx, e.account, token, bcard, blocked.proof()); err == nil || err.Error() != strangerErr.Error() {
		t.Fatalf("a blocked caller at the cap heard %v; a stranger heard %v", err, strangerErr)
	}
	ask, _, err := e.m.CreateInvite(ctx, e.account, InviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := e.m.RedeemAs(ctx, e.account, ask, card, stranger.proof()); err != nil || res.Status != "pending" {
		t.Fatalf("a request at the cap: %+v %v, want it waiting for the owner", res, err)
	}
}

// A root that left and comes back at a new address is added again when the owner approves it — one
// more contact, held to the cap. Re-pinning a contact already held adds nothing and is not refused.
func TestApprovingANewAddressIsHeldToTheCap(t *testing.T) {
	e := capped(t)
	ctx := context.Background()
	back, _, _ := guest(t, "Back")
	if err := e.st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: e.account, Root: back.Fingerprint, Endpoint: back.Host.Endpoint, Leaf: back.Host.LeafDER}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.DecideAddress(ctx, e.account, back.Fingerprint, true); !errors.Is(err, ErrContactCap) {
		t.Fatalf("approving a returning root at the cap: %v", err)
	}
	if _, err := e.st.GetPendingAddress(ctx, e.account, back.Fingerprint); err != nil {
		t.Fatal("a refused approval dropped the waiting address")
	}
	held, _, _ := guest(t, "Held")
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.account, Fingerprint: held.Fingerprint, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: e.account, Root: held.Fingerprint, Endpoint: held.Host.Endpoint, Leaf: held.Host.LeafDER}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.DecideAddress(ctx, e.account, held.Fingerprint, true); err != nil {
		t.Fatalf("re-pinning a held contact over the cap was refused: %v", err)
	}
}

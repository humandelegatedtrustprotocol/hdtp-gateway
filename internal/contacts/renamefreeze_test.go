package contacts

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// update_contact is available at contact tier regardless of permissions, and it
// replaces the stored CARD -- which carries FN, the name the owner reads. If a
// refresh also moved display_name, then a contact accepted as "Alina" could rename
// itself to "Bharat" afterwards, and the owner's decision to trust the name they
// approved would be worth nothing. Whatever else a refresh moves, the label the
// owner accepted stays put.
//
// The cost is deliberate and worth stating: a contact who legitimately changes
// their name does not propagate it, and the owner has no way to accept the new
// one. That is the safe direction to be wrong in until petnames exist.
//
// This test used to prove it over a 1.x rotation, where a new card was endorsed by
// a signature from the old key. 2.0 has no rotation, so it proves the same thing
// over the card refresh that replaced it -- and it FAILED when it was first run
// that way: the 2.0 branch passed the new card's FN straight through.
func TestACardRefreshCannotRenameAPinnedContact(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	g, card, spki := guest(t, "Alina")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: g.Fingerprint, SPKI: spki, Status: "active",
		Card: card, DisplayName: "Alina", Protocol: 2, Leaf: g.Host.LeafDER, Endpoint: g.Host.Endpoint,
	}); err != nil {
		t.Fatal(err)
	}

	// The same root, the same leaf -- a genuine refresh -- whose card claims a
	// different person's name.
	renamed := g.Host.Card("Bharat", "required")
	if err := e.m.UpdateContact(ctx, e.account, g.Fingerprint, renamed); err != nil {
		t.Fatalf("a genuine card refresh was refused: %v", err)
	}

	c, err := e.st.GetContact(ctx, e.account, g.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if c.DisplayName != "Alina" {
		t.Errorf("a pinned contact renamed itself to %q by refreshing its card; the "+
			"owner approved %q and would now read somebody else's name", c.DisplayName, "Alina")
	}
	// The card itself is expected to move -- it is what was refreshed.
	if c.Card != renamed {
		t.Error("the refresh did not store the new card")
	}
}

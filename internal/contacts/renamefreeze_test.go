package contacts

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// update_contact is available at contact tier regardless of permissions, and it
// replaces the stored CARD -- which carries FN, the name the owner reads. If a
// re-pin also refreshed display_name, then a contact accepted as "Alina" could
// rename itself to "Bharat" afterwards, and the owner's decision to trust the
// name they approved would be worth nothing. Whatever else rotation moves, the
// label the owner accepted stays put.
//
// The cost is deliberate and worth stating: a contact who legitimately changes
// their name does not propagate it, and the owner has no way to accept the new
// one. That is the safe direction to be wrong in until petnames exist.
func TestRotationCannotRenameAPinnedContact(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	oldKP, oldCard, oldSPKI := guest(t, "Alina")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: e.account, Fingerprint: oldKP.Fingerprint, SPKI: oldSPKI,
		Status: "active", Card: oldCard, DisplayName: "Alina",
	}); err != nil {
		t.Fatal(err)
	}

	// A genuine, correctly endorsed rotation -- whose new card claims a different
	// person's name.
	newKP, newCard, newSPKI := guest(t, "Bharat")
	h := sha256.Sum256([]byte(newKP.Fingerprint))
	sig, err := ecdsa.SignASN1(rand.Reader, oldKP.Signer.(*ecdsa.PrivateKey), h[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := e.m.UpdateContact(ctx, e.account, oldKP.Fingerprint, newCard, sig, newSPKI); err != nil {
		t.Fatalf("a properly endorsed rotation was refused: %v", err)
	}

	c, err := e.st.GetContact(ctx, e.account, newKP.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if c.DisplayName != "Alina" {
		t.Errorf("a pinned contact renamed itself to %q by rotating its card; the "+
			"owner approved %q and would now read somebody else's name",
			c.DisplayName, "Alina")
	}
	// The card itself is expected to move -- it carries the new key.
	if c.Card != newCard {
		t.Errorf("the rotation did not store the new card")
	}
}

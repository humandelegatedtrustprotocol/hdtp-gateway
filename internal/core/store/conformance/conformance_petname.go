package conformance

import (
	"context"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// petnames is the suite for the owner's petname for a contact.
func petnames(t *testing.T, newStore Factory) {
	// The petname is the OWNER's name for a contact -- optional, local, and the
	// only name no peer can influence. display_name is the contact's own claim,
	// so several contacts may honestly share one; this is the field that settles
	// which is which.
	t.Run("PetnameIsLocalAndSurvivesAMove", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "pn", DisplayName: "PN", Algo: "p256"})
		if _, err := s.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: "sha256:pn1", SPKI: []byte{7},
			Status: "active", DisplayName: "Alice", Card: "BEGIN:VCARD...",
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetContactPetname(ctx, a.ID, "sha256:pn1", "Alice from work"); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetContact(ctx, a.ID, "sha256:pn1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Petname != "Alice from work" {
			t.Errorf("GetContact dropped the petname: %q", got.Petname)
		}
		if got.DisplayName != "Alice" {
			t.Errorf("naming a contact overwrote the name THEY supplied: %q", got.DisplayName)
		}
		all, err := s.ListContacts(ctx, a.ID)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v (%d rows)", err, len(all))
		}
		if all[0].Petname != "Alice from work" {
			t.Errorf("ListContacts dropped the petname, which is the path the portal renders: %q",
				all[0].Petname)
		}

		// A move re-pins the contact at a new address. The petname is the owner's,
		// not the contact's, so nothing a peer does must discard it -- that would
		// hand a peer a way to shed a name the owner gave them. It used to be proved
		// over a 1.x rotation, which re-pinned under a NEW fingerprint; a root never
		// moves, so the re-pin that exists now keeps the fingerprint and changes the
		// address.
		if err := s.RepinContactAddress(ctx, a.ID, "sha256:pn1", "https://moved.example/mcp", []byte("leaf"), []byte{8}, 1756000001); err != nil {
			t.Fatal(err)
		}
		after, err := s.GetContact(ctx, a.ID, "sha256:pn1")
		if err != nil {
			t.Fatal(err)
		}
		if after.Petname != "Alice from work" {
			t.Errorf("a move dropped the owner's own name for the contact: %q", after.Petname)
		}

		// Clearing is how the owner goes back to the contact's own name.
		if err := s.SetContactPetname(ctx, a.ID, "sha256:pn1", ""); err != nil {
			t.Fatal(err)
		}
		cleared, err := s.GetContact(ctx, a.ID, "sha256:pn1")
		if err != nil {
			t.Fatal(err)
		}
		if cleared.Petname != "" {
			t.Errorf("petname could not be cleared: %q", cleared.Petname)
		}
	})
}

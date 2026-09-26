package conformance

import (
	"context"
	"testing"
)

// ownerUnderAChosenID is the suite for an owner created under the id a first passkey already names.
func ownerUnderAChosenID(t *testing.T, newStore Factory) {
	// WebAuthn binds a credential to a user handle when the authenticator makes
	// it, and replays that handle on every later login. So a first passkey has to
	// name the owner id BEFORE the owner row exists — which is what this method
	// is for, and why an owner id minted independently made every first passkey
	// unusable for login.
	t.Run("AnOwnerCanBeCreatedUnderAChosenID", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		const chosen = "0123456789abcdef0123456789abcdef"
		o, err := s.CreateOwnerWithID(ctx, chosen, "Chosen")
		if err != nil {
			t.Fatal(err)
		}
		if o.ID != chosen {
			t.Fatalf("owner id is %q, want the chosen %q", o.ID, chosen)
		}
		back, err := s.GetOwner(ctx, chosen)
		if err != nil {
			t.Fatalf("an owner created under a chosen id cannot be read back: %v", err)
		}
		if back.DisplayName != "Chosen" {
			t.Errorf("display name lost: %q", back.DisplayName)
		}
		// An empty id still yields a usable owner rather than an empty-string row.
		auto, err := s.CreateOwnerWithID(ctx, "", "Auto")
		if err != nil {
			t.Fatal(err)
		}
		if auto.ID == "" {
			t.Error("an empty id produced an owner with no id")
		}
	})
}

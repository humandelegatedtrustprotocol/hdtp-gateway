package conformance

import (
	"context"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// memberships is the suite for memberships and their foreign key.
func memberships(t *testing.T, newStore Factory) {
	t.Run("MembershipRoundTripAndFK", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, _ := s.CreateOwnerWithID(ctx, "", "O")
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "ed25519"})
		if err := s.AddMembership(ctx, o.ID, a.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		ms, err := s.ListMembershipsByOwner(ctx, o.ID)
		if err != nil || len(ms) != 1 || ms[0].AccountID != a.ID || ms[0].Role != "admin" {
			t.Fatalf("memberships: %v %+v", err, ms)
		}
		if err := s.AddMembership(ctx, "nope", a.ID, "admin"); err == nil {
			t.Fatal("membership with unknown owner accepted")
		}
		if err := s.RemoveMembership(ctx, o.ID, a.ID); err != nil {
			t.Fatal(err)
		}
		if ms, _ := s.ListMembershipsByOwner(ctx, o.ID); len(ms) != 0 {
			t.Fatal("membership not removed")
		}
	})
}

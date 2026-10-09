package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// integrations is the suite for integrations.
func integrations(t *testing.T, newStore Factory) {
	t.Run("IntegrationsCRUD", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		in, err := s.InsertIntegration(ctx, store.Integration{
			AccountID: a.ID, Slug: "gcal", Transport: "streamable-http",
			Endpoint: "https://cal.example/mcp",
		})
		if err != nil || in.ID == "" || in.Status != "disabled" || in.AuthKind != "none" {
			t.Fatalf("insert: %+v %v", in, err)
		}
		// slug unique per account
		if _, err := s.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "gcal", Transport: "sse"}); err == nil {
			t.Fatal("duplicate slug accepted")
		}
		got, err := s.GetIntegration(ctx, a.ID, "gcal")
		if err != nil || got.Endpoint != "https://cal.example/mcp" {
			t.Fatalf("get: %+v %v", got, err)
		}
		if byID, err := s.GetIntegrationByID(ctx, in.ID); err != nil || byID.Slug != "gcal" {
			t.Fatalf("get by id: %+v %v", byID, err)
		}
		// The account-bound read: the row for its account; for another account, or an id that is
		// nobody's, one error wrapping ErrNotFound that reads the same, so a door built on it
		// cannot tell a caller which of the two it named.
		if own, err := s.GetAccountIntegration(ctx, a.ID, in.ID); err != nil || own.Slug != "gcal" {
			t.Fatalf("get by account and id: %+v %v", own, err)
		}
		other, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		_, foreignErr := s.GetAccountIntegration(ctx, other.ID, in.ID)
		_, missingErr := s.GetAccountIntegration(ctx, a.ID, "missing")
		if !errors.Is(foreignErr, store.ErrNotFound) || !errors.Is(missingErr, store.ErrNotFound) {
			t.Fatalf("another account's integration: %v; a missing id: %v; want both to wrap ErrNotFound", foreignErr, missingErr)
		}
		if foreignErr.Error() != missingErr.Error() {
			t.Fatalf("another account's integration and a missing id are told apart: %q vs %q", foreignErr, missingErr)
		}
		if err := s.UpdateIntegrationStatus(ctx, in.ID, "ok"); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateIntegrationConfig(ctx, in.ID, "sse", "https://cal2.example/sse", "", "static"); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetIntegration(ctx, a.ID, "gcal")
		if got.Status != "ok" || got.Transport != "sse" || got.AuthKind != "static" || got.UpdatedAt < got.CreatedAt {
			t.Fatalf("after updates: %+v", got)
		}
		all, err := s.ListIntegrations(ctx, a.ID)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v %d", err, len(all))
		}
		if err := s.UpdateIntegrationStatus(ctx, "missing", "ok"); err == nil {
			t.Fatal("status update on unknown id accepted")
		}
		if err := s.DeleteIntegration(ctx, in.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetIntegration(ctx, a.ID, "gcal"); err == nil {
			t.Fatal("deleted integration still readable")
		}
	})
}

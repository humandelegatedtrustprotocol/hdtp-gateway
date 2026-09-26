package conformance

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
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

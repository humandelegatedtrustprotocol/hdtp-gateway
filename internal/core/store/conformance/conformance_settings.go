package conformance

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// settings is the suite for the owner's settings and their secret flag.
func settings(t *testing.T, newStore Factory) {
	t.Run("SettingsUpsertAndSecretFlag", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		if rows, err := s.ListSettings(ctx); err != nil || len(rows) != 0 {
			t.Fatalf("initial settings: %v %d", err, len(rows))
		}
		if err := s.PutSetting(ctx, store.Setting{Key: "seal", Value: "required", UpdatedAt: 100}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutSetting(ctx, store.Setting{
			Key: "tunnel.tailscale.auth_key", Value: "sealed-bytes", Secret: true, UpdatedAt: 101,
		}); err != nil {
			t.Fatal(err)
		}
		// a second write to the same key REPLACES it rather than duplicating
		if err := s.PutSetting(ctx, store.Setting{Key: "seal", Value: "optional", UpdatedAt: 102}); err != nil {
			t.Fatal(err)
		}
		rows, err := s.ListSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("upsert duplicated rows: %+v", rows)
		}
		byKey := map[string]store.Setting{}
		for _, r := range rows {
			byKey[r.Key] = r
		}
		if got := byKey["seal"]; got.Value != "optional" || got.Secret || got.UpdatedAt != 102 {
			t.Fatalf("seal row: %+v", got)
		}
		if got := byKey["tunnel.tailscale.auth_key"]; !got.Secret || got.Value != "sealed-bytes" {
			t.Fatalf("secret flag lost: %+v", got)
		}
		// Unpairing has to FORGET a setting, not blank it.
		if err := s.DeleteSetting(ctx, "tunnel.tailscale.auth_key"); err != nil {
			t.Fatal(err)
		}
		rows, err = s.ListSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Key != "seal" {
			t.Fatalf("after delete: %+v", rows)
		}
		// deleting what is not there is not an error — unpair must be idempotent
		if err := s.DeleteSetting(ctx, "tunnel.tailscale.auth_key"); err != nil {
			t.Fatalf("second delete: %v", err)
		}
	})
}

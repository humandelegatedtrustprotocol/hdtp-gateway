package conformance

import (
	"context"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// ownersAndAccounts is the suite for owners and accounts: creation, constraints and the key an account binds once.
func ownersAndAccounts(t *testing.T, newStore Factory) {
	t.Run("OwnerCRUD", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, err := s.CreateOwnerWithID(ctx, "", "Sumit")
		if err != nil {
			t.Fatal(err)
		}
		if o.ID == "" || o.DisplayName != "Sumit" {
			t.Fatalf("bad owner: %+v", o)
		}
		got, err := s.GetOwner(ctx, o.ID)
		if err != nil || got.DisplayName != "Sumit" {
			t.Fatalf("get: %v %+v", err, got)
		}
		all, err := s.ListOwners(ctx)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v %d", err, len(all))
		}
		if err := s.DeleteOwner(ctx, o.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetOwner(ctx, o.ID); err == nil {
			t.Fatal("deleted owner still readable")
		}
	})

	t.Run("AccountCRUDAndConstraints", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "work", DisplayName: "Work", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Seal != "required" || a.Status != "active" {
			t.Fatalf("defaults wrong: %+v", a)
		}
		if _, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "work", DisplayName: "Dup", Algo: "p256"}); err == nil {
			t.Fatal("duplicate slug accepted")
		}
		got, err := s.GetAccountBySlug(ctx, "work")
		if err != nil || got.ID != a.ID {
			t.Fatalf("get by slug: %v", err)
		}
		if _, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "x", DisplayName: "X", Algo: "rsa"}); err == nil {
			t.Fatal("invalid algo accepted")
		}
	})

	t.Run("AccountKeyBindsOnce", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "k", DisplayName: "K", Algo: "p256"})
		if err := s.SetAccountKey(ctx, a.ID, "sha256:abc", []byte{9}); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetAccountBySlug(ctx, "k")
		if got.Fingerprint != "sha256:abc" {
			t.Fatalf("fingerprint not stored: %+v", got)
		}
		if err := s.SetAccountKey(ctx, a.ID, "sha256:other", []byte{1}); err == nil {
			t.Fatal("re-keying via SetAccountKey must be refused")
		}
	})

}

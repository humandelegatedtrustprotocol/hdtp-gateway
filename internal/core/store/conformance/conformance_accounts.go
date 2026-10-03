package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

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

	// L3 (review 2026-09-28). An identity leaving writes the reserved address and erases the account
	// in one transaction; a create of the same slug that arrives meanwhile must see the reservation.
	// On Postgres the create's check ran before the leave committed and its insert then waited on
	// the slug's unique index, so it went through once the leave committed; a lock on the slug,
	// taken by both, makes the create wait for the leave and then read what it wrote. SQLite's
	// transactions run one at a time already.
	t.Run("ALeaveAndACreateOfItsSlugDoNotRace", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "gone", DisplayName: "G", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		inside, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- s.Atomically(ctx, func(tx store.Store) error {
				if err := tx.UpsertVacatedAddress(ctx, store.VacatedAddress{Endpoint: "https://n.example/a/gone/mcp", Slug: "gone", UntilAt: time.Now().Add(time.Hour).Unix(), At: time.Now().Unix()}); err != nil {
					return err
				}
				if _, err := tx.DeleteAccount(ctx, a.ID); err != nil {
					return err
				}
				close(inside)
				<-release
				return nil
			})
		}()
		<-inside
		created := make(chan error, 1)
		go func() {
			_, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "gone", DisplayName: "Other", Algo: "p256"})
			created <- err
		}()
		time.Sleep(300 * time.Millisecond) // the create is waiting on the leave by now
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-created; !errors.Is(err, store.ErrAddressVacated) {
			t.Fatalf("a create racing the leave of its slug: %v, want the address refused as vacated", err)
		}
	})
}

package conformance

import (
	"context"
	"sync"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// credentials is the suite for credentials, and the last passkey that cannot be removed.
func credentials(t *testing.T, newStore Factory) {
	t.Run("CredentialsInsertAndCount", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, _ := s.CreateOwnerWithID(ctx, "", "O")
		if n, err := s.CountCredentialsByKind(ctx, "passkey"); err != nil || n != 0 {
			t.Fatalf("initial count: %v %d", err, n)
		}
		if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "passkey", Tag: "phone", Data: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "bogus", Data: []byte{1}}); err == nil {
			t.Fatal("invalid credential kind accepted")
		}
		if n, _ := s.CountCredentialsByKind(ctx, "passkey"); n != 1 {
			t.Fatalf("count after insert: %d", n)
		}
	})

	// P10-09d: the "never remove the last passkey" invariant is one statement,
	// not a read followed by a delete. Two surfaces (portal, owner MCP) can both
	// be removing at once, and check-then-delete lets both observe "there are
	// two" and both delete — leaving zero, which locks the owner out AND
	// re-opens the setup wizard to whoever reaches the node first.
	t.Run("RemoveCredentialIfNotLastKeepsTheLastOne", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, _ := s.CreateOwnerWithID(ctx, "", "O")
		var ids []string
		// Eight, not two: the invariant is "never reach zero" under ANY amount
		// of simultaneity, and a two-way race is a window narrow enough to pass
		// by luck on a fast database.
		for _, tag := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "passkey", Tag: tag, Data: []byte(tag)}); err != nil {
				t.Fatal(err)
			}
		}
		list, err := s.ListCredentialsByKind(ctx, "passkey")
		if err != nil || len(list) != 8 {
			t.Fatalf("setup: %v %d", err, len(list))
		}
		for _, c := range list {
			ids = append(ids, c.ID)
		}

		// CONCURRENTLY, because sequential removal cannot fail: a read-then-delete
		// implementation passes that, and so does an uncorrelated `SELECT
		// COUNT(*)` on Postgres, where READ COMMITTED lets two statements each
		// see "there are two" and each delete a different row. The invariant is
		// about simultaneity, so the test has to be.
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]bool, len(ids))
		errs := make([]error, len(ids))
		for i, id := range ids {
			wg.Add(1)
			go func(i int, id string) {
				defer wg.Done()
				<-start
				results[i], errs[i] = s.RemoveCredentialIfNotLast(ctx, id, "passkey")
			}(i, id)
		}
		close(start)
		wg.Wait()
		removedCount := 0
		for i := range ids {
			if errs[i] != nil {
				t.Fatal(errs[i])
			}
			if results[i] {
				removedCount++
			}
		}
		if removedCount != len(ids)-1 {
			t.Fatalf("removed %d of %d passkeys concurrently, want %d",
				removedCount, len(ids), len(ids)-1)
		}
		n, err := s.CountCredentialsByKind(ctx, "passkey")
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("passkeys left: %d, want exactly 1 — reaching zero locks the owner "+
				"out AND re-opens the setup wizard to whoever finds the node", n)
		}
		// The count is scoped to the KIND. A credential of another kind must not
		// make the last passkey look removable.
		if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "oauth", Tag: "up", Data: []byte("t")}); err != nil {
			t.Fatal(err)
		}
		left, _ := s.ListCredentialsByKind(ctx, "passkey")
		if removed, err := s.RemoveCredentialIfNotLast(ctx, left[0].ID, "passkey"); err != nil || removed {
			t.Fatalf("another kind made the last passkey removable: removed=%v err=%v", removed, err)
		}
	})
}

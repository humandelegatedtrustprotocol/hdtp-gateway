package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// migrations is the suite for the schema migrates up, down and up again, empty and with data present.
func migrations(t *testing.T, newStore Factory) {
	t.Run("MigrateUpDownUp", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("up: %v", err)
		}
		if err := s.MigrateDown(ctx); err != nil {
			t.Fatalf("down: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("re-up: %v", err)
		}
	})

	// MigrateUpDownUp above runs against an EMPTY database, so every
	// down-migration branch that handles DATA is never executed — and that is
	// the half that can fail. 0021 narrows the messages uniqueness key on the
	// way down and must first drop rows that are legal under the wide key and
	// collide under the narrow one; 0024 must rewrite a status the older CHECK
	// constraint does not allow. Both are exactly the shape that works on an
	// empty table and destroys, or refuses, a populated one.
	t.Run("MigrateDownAndUpWithDataPresent", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "roll", DisplayName: "Roll", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		// The two rows a naive rollback trips over: a msg_id used in BOTH
		// directions (legal now, a duplicate under the older key), and a status
		// the older CHECK constraint does not know.
		rows := []store.Message{
			{ID: "r1", MsgID: "shared", Direction: "in", Status: "delivered"},
			{ID: "r2", MsgID: "shared", Direction: "out", Status: "failed"},
			{ID: "r3", MsgID: "solo", Direction: "out", Status: "pending"},
		}
		for _, m := range rows {
			m.AccountID, m.ContactFpr, m.ThreadID = a.ID, "sha256:p", "t1"
			m.Sender, m.Kind, m.Body, m.CreatedAt = "human", "text", m.ID, 100
			if err := s.InsertMessage(ctx, m); err != nil {
				t.Fatalf("seeding %s: %v", m.ID, err)
			}
		}

		// A full rollback runs every down-migration in reverse WITH these rows
		// present, then drops the tables — so what this pins is that the
		// down-path does not FAIL on real data. 0021 must dedupe the shared
		// msg_id before it can narrow the key (the rebuild's INSERT would hit
		// the UNIQUE constraint otherwise), and 0019 must rewrite `failed` and
		// `pending` before it can reinstate the CHECK that knew neither.
		//
		// It cannot assert the rows survive: DownTo(0) drops the schema by
		// design. That is what a full rollback means, and a test claiming
		// otherwise would be pinning a promise the tool does not make.
		if err := s.MigrateDown(ctx); err != nil {
			t.Fatalf("rolling back a populated database failed — a down-migration that "+
				"errors here leaves an operator half-migrated: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("re-applying after a populated rollback failed: %v", err)
		}

		// And the schema that comes back is the current one: a msg_id may be
		// used once in each direction.
		a2, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "roll2", DisplayName: "Roll2", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t2", AccountID: a2.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		for i, dir := range []string{"in", "out"} {
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("post%d", i), AccountID: a2.ID, ContactFpr: "sha256:p",
				MsgID: "shared", ThreadID: "t2", Direction: dir, Sender: "human",
				Kind: "text", Body: dir, Status: "delivered", CreatedAt: 100,
			}); err != nil {
				t.Fatalf("after a rollback and re-up the %s direction was refused: %v", dir, err)
			}
		}
	})
}

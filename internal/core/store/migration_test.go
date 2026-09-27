package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// AC: migration 0019 REBUILDS the messages table — SQLite cannot alter a CHECK
// constraint — and a rebuild is the one migration shape that can silently lose
// data. Rows, their sequence numbers and their statuses must all survive, and
// the widened CHECK must still reject a status outside the set.
//
// The rebuild runs on a live owner's conversation history. "It compiled" is not
// evidence about that.
func TestMessageTableRebuildPreservesHistory(t *testing.T) {
	ctx := context.Background()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertThread(ctx, store.Thread{
		ID: "t1", AccountID: a.ID, ContactFpr: "sha256:c", CreatedAt: 1, LastAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	for i, st := range []string{"delivered", "queued_for_human", "pending", "failed"} {
		if err := s.InsertMessage(ctx, store.Message{
			AccountID: a.ID, ContactFpr: "sha256:c", MsgID: string(rune('a' + i)),
			ThreadID: "t1", Direction: "in", Sender: "human", Kind: "text",
			Body: "body" + st, Status: st, CreatedAt: int64(100 + i),
		}); err != nil {
			t.Fatalf("status %q was rejected after the rebuild: %v", st, err)
		}
	}

	msgs, err := s.ListMessagesByThread(ctx, a.ID, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("kept %d of 4 messages", len(msgs))
	}
	// Sequence numbers must be strictly increasing: the rebuild copies `seq`
	// explicitly so that ordering — and any external reference to it — holds.
	for i := 1; i < len(msgs); i++ {
		if msgs[i].Seq <= msgs[i-1].Seq {
			t.Fatalf("seq is not increasing after the rebuild: %d then %d", msgs[i-1].Seq, msgs[i].Seq)
		}
	}
	// The default expiry is 0 = "unset", which the sweeper reads as 24h.
	if msgs[0].ExpiresAt != 0 {
		t.Fatalf("expires_at default is %d, want 0", msgs[0].ExpiresAt)
	}
	// The CHECK was widened, not removed.
	if err := s.InsertMessage(ctx, store.Message{
		AccountID: a.ID, ContactFpr: "sha256:c", MsgID: "bogus", ThreadID: "t1",
		Direction: "in", Sender: "human", Kind: "text", Body: "x",
		Status: "not-a-status", CreatedAt: 200,
	}); err == nil {
		t.Fatal("the rebuild dropped the status CHECK: an arbitrary status was accepted")
	}
	// And the uniqueness that idempotency depends on survives (§7.2).
	if err := s.InsertMessage(ctx, store.Message{
		AccountID: a.ID, ContactFpr: "sha256:c", MsgID: "a", ThreadID: "t1",
		Direction: "in", Sender: "human", Kind: "text", Body: "dup",
		Status: "delivered", CreatedAt: 300,
	}); err == nil {
		t.Fatal("the rebuild dropped UNIQUE(account, contact, msg_id) — idempotency is gone")
	}
}

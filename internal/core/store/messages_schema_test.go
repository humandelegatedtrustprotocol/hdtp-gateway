package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// What the messages table holds a row to: each of the four statuses is accepted and no
// other, rows keep the order they were written in, the expiry starts unset, and a message
// id is taken once per contact and direction.
func TestMessagesKeepTheirOrderStatusesAndUniqueness(t *testing.T) {
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
			t.Fatalf("status %q was rejected: %v", st, err)
		}
	}

	msgs, err := s.ListMessagesByThread(ctx, a.ID, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("kept %d of 4 messages", len(msgs))
	}
	// Sequence numbers must be strictly increasing: a thread is read in `seq` order.
	for i := 1; i < len(msgs); i++ {
		if msgs[i].Seq <= msgs[i-1].Seq {
			t.Fatalf("seq is not increasing: %d then %d", msgs[i-1].Seq, msgs[i].Seq)
		}
	}
	// The default expiry is 0 = "unset", which the sweeper reads as 24h.
	if msgs[0].ExpiresAt != 0 {
		t.Fatalf("expires_at default is %d, want 0", msgs[0].ExpiresAt)
	}
	// A status outside the four is refused.
	if err := s.InsertMessage(ctx, store.Message{
		AccountID: a.ID, ContactFpr: "sha256:c", MsgID: "bogus", ThreadID: "t1",
		Direction: "in", Sender: "human", Kind: "text", Body: "x",
		Status: "not-a-status", CreatedAt: 200,
	}); err == nil {
		t.Fatal("an arbitrary status was accepted: the status CHECK is gone")
	}
	// And the uniqueness that idempotency depends on (§7.2).
	if err := s.InsertMessage(ctx, store.Message{
		AccountID: a.ID, ContactFpr: "sha256:c", MsgID: "a", ThreadID: "t1",
		Direction: "in", Sender: "human", Kind: "text", Body: "dup",
		Status: "delivered", CreatedAt: 300,
	}); err == nil {
		t.Fatal("a second message with one id, contact and direction was accepted: idempotency is gone")
	}
}

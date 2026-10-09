package conformance

import (
	"context"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// conversationDeletion is the suite for deleting one conversation (SPEC §7.9): the primitives
// messaging.Service.DeleteThread runs in one transaction, each reaching this thread of this account
// and nothing else, and the touch that tells a message being recorded its thread went.
func conversationDeletion(t *testing.T, newStore Factory) {
	t.Run("DeleteOneThread", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "del", DisplayName: "Del", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "del-b", DisplayName: "Del B", Algo: "p256"})
		threads := []store.Thread{
			{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p"}, // the one deleted
			{ID: "t2", AccountID: a.ID, ContactFpr: "sha256:p"}, // the same contact's other thread
			{ID: "t1", AccountID: b.ID, ContactFpr: "sha256:p"}, // another account's thread of the same id
		}
		for _, th := range threads {
			th.CreatedAt, th.LastAt = 100, 100
			if err := s.InsertThread(ctx, th); err != nil {
				t.Fatal(err)
			}
		}
		msgs := []store.Message{
			{ID: "a1", AccountID: a.ID, ThreadID: "t1", MsgID: "a1", Direction: "in", Kind: "text", Body: "hi", Status: "delivered"},
			{ID: "a2", AccountID: a.ID, ThreadID: "t1", MsgID: "a2", Direction: "in", Kind: "media", Body: `{"hash":"h1"}`, Status: "delivered"},
			{ID: "a3", AccountID: a.ID, ThreadID: "t1", MsgID: "a3", Direction: "out", Kind: "text", Body: "yo", Status: "pending"},
			{ID: "a4", AccountID: a.ID, ThreadID: "t2", MsgID: "a4", Direction: "in", Kind: "media", Body: `{"hash":"h2"}`, Status: "delivered"},
			{ID: "b1", AccountID: b.ID, ThreadID: "t1", MsgID: "b1", Direction: "in", Kind: "media", Body: `{"hash":"hb"}`, Status: "delivered"},
		}
		for _, m := range msgs {
			m.ContactFpr, m.Sender, m.CreatedAt = "sha256:p", "human", 100
			if err := s.InsertMessage(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range []store.Change{
			{AccountID: a.ID, Kind: "message", ThreadID: "t1"},
			{AccountID: a.ID, Kind: "message", ThreadID: "t2"},
			{AccountID: b.ID, Kind: "message", ThreadID: "t1"},
		} {
			c.At = 100
			if _, err := s.AppendChange(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := s.PutIdempotency(ctx, a.ID, "sha256:p", "a1", "{}", 0); err != nil {
			t.Fatal(err)
		}

		if bodies, err := s.ListThreadMediaBodies(ctx, a.ID, "t1"); err != nil || len(bodies) != 1 || bodies[0] != `{"hash":"h1"}` {
			t.Fatalf("ListThreadMediaBodies = %v, %v; want the one media body of this thread", bodies, err)
		}
		if n, err := s.DeleteThread(ctx, a.ID, "t1"); err != nil || n != 1 {
			t.Fatalf("DeleteThread = %d, %v", n, err)
		}
		if n, err := s.DeleteThreadMessages(ctx, a.ID, "t1"); err != nil || n != 3 {
			t.Fatalf("DeleteThreadMessages = %d, %v; want the thread's three, pending outbound included", n, err)
		}
		if n, err := s.DeleteChangesByThread(ctx, a.ID, "t1"); err != nil || n != 1 {
			t.Fatalf("DeleteChangesByThread = %d, %v", n, err)
		}

		if _, err := s.GetThread(ctx, a.ID, "t1"); err == nil {
			t.Fatal("the deleted thread is still there")
		}
		if pending, _ := s.ListPendingOutbound(ctx, 10); len(pending) != 0 {
			t.Fatalf("a deleted thread's outbound message is still waiting to be retried: %+v", pending)
		}
		if _, err := s.GetThread(ctx, a.ID, "t2"); err != nil {
			t.Fatalf("the same contact's other thread went: %v", err)
		}
		if left, _ := s.ListMessagesByThread(ctx, a.ID, "t2"); len(left) != 1 {
			t.Fatalf("the other thread holds %d messages, want 1", len(left))
		}
		if _, err := s.GetThread(ctx, b.ID, "t1"); err != nil {
			t.Fatalf("another account's thread of the same id went: %v", err)
		}
		if left, _ := s.ListMessagesByThread(ctx, b.ID, "t1"); len(left) != 1 {
			t.Fatalf("another account's thread holds %d messages, want 1", len(left))
		}
		if mine, _ := s.AccountChangesAfter(ctx, a.ID, 0, 10); len(mine) != 1 || mine[0].ThreadID != "t2" {
			t.Fatalf("this account's change log = %+v, want t2's row only", mine)
		}
		if theirs, _ := s.AccountChangesAfter(ctx, b.ID, 0, 10); len(theirs) != 1 {
			t.Fatalf("another account's change log lost a row: %+v", theirs)
		}
		if _, existed, err := s.PutIdempotency(ctx, a.ID, "sha256:p", "a1", "{}", 0); err != nil || !existed {
			t.Fatalf("the idempotency record went with the conversation (existed=%v, %v); HDTP §13.3 keeps it for its window", existed, err)
		}

		// A thread that is gone: nothing to delete, nothing to touch.
		if n, err := s.DeleteThread(ctx, a.ID, "t1"); err != nil || n != 0 {
			t.Fatalf("DeleteThread again = %d, %v; want 0", n, err)
		}
		if n, err := s.TouchThread(ctx, a.ID, "t1", 200); err != nil || n != 0 {
			t.Fatalf("TouchThread on a deleted thread = %d, %v; want 0", n, err)
		}
		if n, err := s.TouchThread(ctx, a.ID, "t2", 200); err != nil || n != 1 {
			t.Fatalf("TouchThread = %d, %v; want 1", n, err)
		}
	})

	t.Run("RecordAFetchedFileOnItsMessage", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "fetch", DisplayName: "Fetch", Algo: "p256"})
		if err := s.InsertMessage(ctx, store.Message{ID: "u1", AccountID: a.ID, ContactFpr: "sha256:p", MsgID: "u1", ThreadID: "t1",
			Direction: "in", Sender: "human", Kind: "media", Body: `{"url":"https://x"}`, Status: "delivered", CreatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertMessage(ctx, store.Message{ID: "x1", AccountID: a.ID, ContactFpr: "sha256:p", MsgID: "x1", ThreadID: "t1",
			Direction: "in", Sender: "human", Kind: "text", Body: "words", Status: "delivered", CreatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		m, err := s.GetMessage(ctx, a.ID, "u1")
		if err != nil || m.Body != `{"url":"https://x"}` {
			t.Fatalf("GetMessage = %+v, %v", m, err)
		}
		if _, err := s.GetMessage(ctx, "another-account", "u1"); err == nil {
			t.Fatal("GetMessage answered another account's message")
		}
		if n, err := s.SetMediaBody(ctx, a.ID, "u1", `{"url":"https://x","hash":"h"}`); err != nil || n != 1 {
			t.Fatalf("SetMediaBody = %d, %v", n, err)
		}
		if n, err := s.SetMediaBody(ctx, a.ID, "x1", `{"hash":"h"}`); err != nil || n != 0 {
			t.Fatalf("SetMediaBody rewrote a text message: %d, %v", n, err)
		}
		if bodies, _ := s.ListMediaBodies(ctx, a.ID); len(bodies) != 1 || bodies[0] != `{"url":"https://x","hash":"h"}` {
			t.Fatalf("ListMediaBodies = %v; want the fetched file named", bodies)
		}
	})
}

package conformance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// retention is the suite for retention: the primitives the sweeper uses, and the idempotency windows that close.
func retention(t *testing.T, newStore Factory) {
	t.Run("RetentionPrimitives", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ret", DisplayName: "Ret", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		for i, ts := range []int64{100, 500} {
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("m%d", i), AccountID: a.ID, ContactFpr: "sha256:p",
				MsgID: fmt.Sprintf("msg%d", i), ThreadID: "t1", Direction: "in",
				Sender: "human", Kind: "text", Body: "hi", Status: "delivered", CreatedAt: ts,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: "deadbeef", Size: 10, CreatedAt: 100}); err != nil {
			t.Fatal(err)
		}
		// SumBlobBytes drives the media quota, and on Postgres SUM(bigint) is
		// NUMERIC — a scan that missed the type silently answered 0 and the
		// quota never bit. This is what pins the conversion on both engines.
		if used, err := s.SumBlobBytes(ctx, a.ID); err != nil || used != 10 {
			t.Fatalf("SumBlobBytes = %d, %v; want 10", used, err)
		}
		// only what is older than the cutoff goes
		n, err := s.DeleteMessagesBefore(ctx, a.ID, 300)
		if err != nil || n != 1 {
			t.Fatalf("DeleteMessagesBefore: %d %v", n, err)
		}
		if msgs, _ := s.ListMessagesByThread(ctx, a.ID, "t1"); len(msgs) != 1 {
			t.Fatalf("%d messages remain, want 1", len(msgs))
		}
		// the thread still has a message, so it stays
		if n, err := s.DeleteEmptyThreads(ctx, a.ID); err != nil || n != 0 {
			t.Fatalf("DeleteEmptyThreads removed a non-empty thread: %d %v", n, err)
		}
		if _, err := s.DeleteMessagesBefore(ctx, a.ID, 1000); err != nil {
			t.Fatal(err)
		}
		// Another account's thread of the SAME id, with a message in it: it neither keeps this
		// account's empty thread alive nor goes with it.
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ret-b", DisplayName: "Ret B", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: b.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertMessage(ctx, store.Message{ID: "mb", AccountID: b.ID, ContactFpr: "sha256:p", MsgID: "msgb", ThreadID: "t1",
			Direction: "in", Sender: "human", Kind: "text", Body: "hi", Status: "delivered", CreatedAt: 100}); err != nil {
			t.Fatal(err)
		}
		if n, err := s.DeleteEmptyThreads(ctx, a.ID); err != nil || n != 1 {
			t.Fatalf("DeleteEmptyThreads: %d %v", n, err)
		}
		if n, err := s.DeleteEmptyThreads(ctx, b.ID); err != nil || n != 0 {
			t.Fatalf("DeleteEmptyThreads removed another account's thread that has a message: %d %v", n, err)
		}
		// media bodies: only the media messages, only this account's, oldest first
		for i, m := range []store.Message{
			{ID: "md2", AccountID: a.ID, MsgID: "md2", Kind: "media", Body: `{"hash":"two"}`, CreatedAt: 2000},
			{ID: "md1", AccountID: a.ID, MsgID: "md1", Kind: "media", Body: `{"hash":"one"}`, CreatedAt: 3000},
			{ID: "tx1", AccountID: a.ID, MsgID: "tx1", Kind: "text", Body: "not media", CreatedAt: 3000},
			{ID: "mdb", AccountID: b.ID, MsgID: "mdb", Kind: "media", Body: `{"hash":"theirs"}`, CreatedAt: 3000},
		} {
			m.ContactFpr, m.ThreadID, m.Direction, m.Sender, m.Status = "sha256:p", "t1", "in", "human", "delivered"
			if err := s.InsertMessage(ctx, m); err != nil {
				t.Fatalf("media fixture %d: %v", i, err)
			}
		}
		if bodies, err := s.ListMediaBodies(ctx, a.ID); err != nil || len(bodies) != 2 || bodies[0] != `{"hash":"two"}` || bodies[1] != `{"hash":"one"}` {
			t.Fatalf("ListMediaBodies = %v, %v; want this account's two media bodies in the order they arrived", bodies, err)
		}
		// blobs: listed, counted across accounts, deleted per account
		blobs, err := s.ListBlobs(ctx, a.ID)
		if err != nil || len(blobs) != 1 {
			t.Fatalf("ListBlobs: %d %v", len(blobs), err)
		}
		if refs, err := s.CountBlobRefs(ctx, "deadbeef"); err != nil || refs != 1 {
			t.Fatalf("CountBlobRefs: %d %v", refs, err)
		}
		if n, err := s.DeleteBlob(ctx, a.ID, "deadbeef"); err != nil || n != 1 {
			t.Fatalf("DeleteBlob: %d %v", n, err)
		}
		if refs, err := s.CountBlobRefs(ctx, "deadbeef"); err != nil || refs != 0 {
			t.Fatalf("refs after delete: %d %v", refs, err)
		}
	})

	// A sealed call writes an idempotency record every time and a sign-in writes a session. Both
	// have a window, and a row past its window goes — or a node holds one for every call it ever
	// took. `now` is the caller's, so the windows are tested without waiting for them.
	t.Run("ClosedWindowsLeave", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "win", DisplayName: "Win", Algo: "p256"})
		now := time.Now().Unix()
		for id, exp := range map[string]int64{"env:closed": now - 1, "env:open": now + 300, "undated": 0} {
			if _, existed, err := s.PutIdempotency(ctx, a.ID, "sha256:p", id, "{}", exp); err != nil || existed {
				t.Fatalf("PutIdempotency %s: existed=%v %v", id, existed, err)
			}
		}
		held := func(id string) bool {
			// A second Put of the same key answers `existed`; one that was removed does not.
			_, existed, err := s.PutIdempotency(ctx, a.ID, "sha256:p", id, "{}", now+300)
			if err != nil {
				t.Fatal(err)
			}
			return existed
		}
		if n, err := s.DeleteExpiredIdempotency(ctx, now); err != nil || n != 1 {
			t.Fatalf("DeleteExpiredIdempotency removed %d, %v; want the one closed record", n, err)
		}
		if !held("env:open") || !held("undated") {
			t.Fatal("a record still inside its window was removed")
		}
		if held("env:closed") {
			t.Fatal("the closed record was still there")
		}
		// The undated record goes once it is older than the window a record without one gets.
		later := now + int64(store.UndatedIdempotencyWindow.Seconds()) + 1
		if n, err := s.DeleteExpiredIdempotency(ctx, later); err != nil || n != 3 {
			t.Fatalf("at the end of the undated window %d went, %v; want all three that remain", n, err)
		}

		o, err := s.CreateOwnerWithID(ctx, "", "Win Owner")
		if err != nil {
			t.Fatal(err)
		}
		for id, exp := range map[string]int64{"s-abandoned": now - 1, "s-live": now + 3600} {
			if err := s.InsertSession(ctx, id, o.ID, now-7200, exp); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := s.DeleteExpiredSessions(ctx, now); err != nil || n != 1 {
			t.Fatalf("DeleteExpiredSessions removed %d, %v; want the abandoned one", n, err)
		}
		if _, _, err := s.GetSession(ctx, "s-live"); err != nil {
			t.Fatalf("the live session went with it: %v", err)
		}
		if _, _, err := s.GetSession(ctx, "s-abandoned"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the abandoned session is still there: %v", err)
		}
	})
}

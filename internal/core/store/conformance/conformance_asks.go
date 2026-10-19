package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// asks is the suite for the owner's asks and notices (internal/services/asks).
func asks(t *testing.T, newStore Factory) {
	setup := func(t *testing.T, slug string) (Migratable, store.Account) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: slug, DisplayName: "A", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"t1", "t2"} {
			if err := s.InsertThread(ctx, store.Thread{ID: id, AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 1, LastAt: 1}); err != nil {
				t.Fatal(err)
			}
		}
		return s, a
	}
	ask := func(a store.Account, id, thread, msg string, at int64) store.OwnerAsk {
		return store.OwnerAsk{ID: id, AccountID: a.ID, Kind: "ask", ThreadID: thread, ContactFpr: "sha256:p", ForMsgID: msg,
			Surface: `[{"id":"` + id + `"}]`, Status: "open", CreatedAt: at, UpdatedAt: at, ExpiresAt: at + 100}
	}

	// Another account's ask answers as one that does not exist, and its writes change nothing.
	t.Run("AnAskIsScopedToItsAccount", func(t *testing.T) {
		s, a := setup(t, "ask-a")
		ctx := context.Background()
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ask-b", DisplayName: "B", Algo: "p256"})
		want := ask(a, "ask_1", "t1", "m1", 1000)
		if ok, err := s.InsertOwnerAsk(ctx, want); !ok || err != nil {
			t.Fatalf("insert: %v %v", ok, err)
		}
		got, err := s.GetOwnerAsk(ctx, a.ID, "ask_1")
		if err != nil || got != want {
			t.Fatalf("the ask did not come back as stored: %+v %v", got, err)
		}
		if _, err := s.GetOwnerAsk(ctx, b.ID, "ask_1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another account's ask must be not found, got %v", err)
		}
		if ok, err := s.CloseOwnerAsk(ctx, b.ID, "ask_1", "answered", "x", 1001); ok || err != nil {
			t.Fatalf("a close by another account: %v %v, want false", ok, err)
		}
		if ok, err := s.ExpireOwnerAsk(ctx, b.ID, "ask_1", 5000); ok || err != nil {
			t.Fatalf("an expiry by another account: %v %v, want false", ok, err)
		}
		if l, err := s.ListOwnerAsks(ctx, b.ID, 10); err != nil || len(l) != 0 {
			t.Fatalf("another account lists %d asks (%v)", len(l), err)
		}
		if after, _ := s.GetOwnerAsk(ctx, a.ID, "ask_1"); after != want {
			t.Fatalf("another account's writes changed the ask: %+v", after)
		}
	})

	// A retry of one ask about one message writes nothing and finds the row it wrote.
	t.Run("AskingTwiceAboutOneMessageIsOneRow", func(t *testing.T) {
		s, a := setup(t, "ask-twice")
		ctx := context.Background()
		first := ask(a, "ask_1", "t1", "m1", 1000)
		if ok, err := s.InsertOwnerAsk(ctx, first); !ok || err != nil {
			t.Fatalf("insert: %v %v", ok, err)
		}
		if ok, err := s.InsertOwnerAsk(ctx, ask(a, "ask_2", "t1", "m1", 1001)); ok || err != nil {
			t.Fatalf("a second ask about one message: %v %v, want false", ok, err)
		}
		got, err := s.GetOwnerAskFor(ctx, a.ID, "ask", "t1", "m1")
		if err != nil || got.ID != "ask_1" {
			t.Fatalf("GetOwnerAskFor: %+v %v, want ask_1", got, err)
		}
		// A notice about the same message is another row: the kind is part of the key.
		n := ask(a, "ntc_1", "t1", "m1", 1002)
		n.Kind, n.Status, n.ExpiresAt = "notice", "posted", 0
		if ok, err := s.InsertOwnerAsk(ctx, n); !ok || err != nil {
			t.Fatalf("a notice about the asked message: %v %v", ok, err)
		}
		if _, err := s.GetOwnerAsk(ctx, a.ID, "ask_2"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the refused ask was written: %v", err)
		}
	})

	// One open ask per thread; closing it lets the next one in, and another thread is apart.
	t.Run("AThreadHasOneOpenAskAtATime", func(t *testing.T) {
		s, a := setup(t, "ask-open")
		ctx := context.Background()
		if ok, err := s.InsertOwnerAsk(ctx, ask(a, "ask_1", "t1", "m1", 1000)); !ok || err != nil {
			t.Fatalf("insert: %v %v", ok, err)
		}
		if ok, err := s.InsertOwnerAsk(ctx, ask(a, "ask_2", "t1", "m2", 1001)); ok || err != nil {
			t.Fatalf("a second open ask on t1: %v %v, want false", ok, err)
		}
		if ok, err := s.InsertOwnerAsk(ctx, ask(a, "ask_3", "t2", "m3", 1001)); !ok || err != nil {
			t.Fatalf("an open ask on t2: %v %v", ok, err)
		}
		open, err := s.GetOpenOwnerAsk(ctx, a.ID, "t1")
		if err != nil || open.ID != "ask_1" {
			t.Fatalf("t1's open ask: %+v %v", open, err)
		}
		if ok, err := s.CloseOwnerAsk(ctx, a.ID, "ask_1", "answered", `Ana chose: "Yes"`, 1002); !ok || err != nil {
			t.Fatalf("close: %v %v", ok, err)
		}
		if ok, err := s.CloseOwnerAsk(ctx, a.ID, "ask_1", "withdrawn", "", 1003); ok || err != nil {
			t.Fatalf("a second close: %v %v, want false", ok, err)
		}
		got, _ := s.GetOwnerAsk(ctx, a.ID, "ask_1")
		if got.Status != "answered" || got.AnswerText != `Ana chose: "Yes"` || got.UpdatedAt != 1002 {
			t.Fatalf("after the close: %+v", got)
		}
		if _, err := s.GetOpenOwnerAsk(ctx, a.ID, "t1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("t1 has no open ask after the close, got %v", err)
		}
		if ok, err := s.InsertOwnerAsk(ctx, ask(a, "ask_2", "t1", "m2", 1004)); !ok || err != nil {
			t.Fatalf("the next ask on t1: %v %v", ok, err)
		}
	})

	// Closing is for an ask still open before its time; expiring for one whose time has come.
	t.Run("CloseAndExpireFollowTheClock", func(t *testing.T) {
		s, a := setup(t, "ask-clock")
		ctx := context.Background()
		if ok, err := s.InsertOwnerAsk(ctx, ask(a, "ask_1", "t1", "m1", 1000)); !ok || err != nil { // expires at 1100
			t.Fatalf("insert: %v %v", ok, err)
		}
		if n, err := s.CountOpenOwnerAsks(ctx, a.ID, 1099); n != 1 || err != nil {
			t.Fatalf("open before expiry: %d %v", n, err)
		}
		if ok, err := s.ExpireOwnerAsk(ctx, a.ID, "ask_1", 1099); ok || err != nil {
			t.Fatalf("an expiry before its time: %v %v, want false", ok, err)
		}
		if due, err := s.ListDueOwnerAsks(ctx, 1099, 10); err != nil || len(due) != 0 {
			t.Fatalf("due before expiry: %d %v", len(due), err)
		}
		if n, _ := s.CountOpenOwnerAsks(ctx, a.ID, 1100); n != 0 {
			t.Fatalf("an ask past its time is not counted open, got %d", n)
		}
		if ok, err := s.CloseOwnerAsk(ctx, a.ID, "ask_1", "answered", "late", 1100); ok || err != nil {
			t.Fatalf("an answer at its expiry: %v %v, want false", ok, err)
		}
		due, err := s.ListDueOwnerAsks(ctx, 1100, 10)
		if err != nil || len(due) != 1 || due[0].ID != "ask_1" || due[0].AccountID != a.ID {
			t.Fatalf("due at expiry: %+v %v", due, err)
		}
		if ok, err := s.ExpireOwnerAsk(ctx, a.ID, "ask_1", 1100); !ok || err != nil {
			t.Fatalf("expire: %v %v", ok, err)
		}
		if ok, _ := s.ExpireOwnerAsk(ctx, a.ID, "ask_1", 1200); ok {
			t.Fatal("an ask expired twice")
		}
		got, _ := s.GetOwnerAsk(ctx, a.ID, "ask_1")
		if got.Status != "expired" || got.AnswerText != "" || got.UpdatedAt != 1100 {
			t.Fatalf("after the expiry: %+v", got)
		}
	})

	t.Run("TheListsAreOrderedAndFiltered", func(t *testing.T) {
		s, a := setup(t, "ask-lists")
		ctx := context.Background()
		for _, x := range []store.OwnerAsk{ask(a, "ask_1", "t1", "m1", 1000), ask(a, "ask_2", "t2", "m2", 1001)} {
			if ok, err := s.InsertOwnerAsk(ctx, x); !ok || err != nil {
				t.Fatal(ok, err)
			}
		}
		n := ask(a, "ntc_1", "t1", "m3", 1002)
		n.Kind, n.Status, n.ExpiresAt = "notice", "posted", 0
		if ok, err := s.InsertOwnerAsk(ctx, n); !ok || err != nil {
			t.Fatal(ok, err)
		}
		if _, err := s.CloseOwnerAsk(ctx, a.ID, "ask_2", "withdrawn", "", 1003); err != nil {
			t.Fatal(err)
		}
		ids := func(l []store.OwnerAsk, err error) []string {
			if err != nil {
				t.Fatal(err)
			}
			out := []string{}
			for _, x := range l {
				out = append(out, x.ID)
			}
			return out
		}
		if got := ids(s.ListOwnerAsks(ctx, a.ID, 10)); len(got) != 3 || got[0] != "ntc_1" || got[2] != "ask_1" {
			t.Fatalf("ListOwnerAsks: %v, want newest first", got)
		}
		if got := ids(s.ListOwnerAsks(ctx, a.ID, 1)); len(got) != 1 {
			t.Fatalf("the limit: %v", got)
		}
		if got := ids(s.ListOpenOwnerAsks(ctx, a.ID, 10)); len(got) != 1 || got[0] != "ask_1" {
			t.Fatalf("ListOpenOwnerAsks: %v, want ask_1 alone", got)
		}
		if got := ids(s.ListContactOwnerAsks(ctx, a.ID, "sha256:p", 10)); len(got) != 3 || got[0] != "ask_1" || got[2] != "ntc_1" {
			t.Fatalf("ListContactOwnerAsks: %v, want oldest first", got)
		}
		if got := ids(s.ListContactOwnerAsks(ctx, a.ID, "sha256:other", 10)); len(got) != 0 {
			t.Fatalf("another contact's: %v", got)
		}
	})

	// A thread's asks and notices go with it, and with no other thread.
	t.Run("AThreadsAsksGoWithIt", func(t *testing.T) {
		s, a := setup(t, "ask-delete")
		ctx := context.Background()
		for _, x := range []store.OwnerAsk{ask(a, "ask_1", "t1", "m1", 1000), ask(a, "ask_2", "t2", "m2", 1001), ask(a, "ask_3", "t3", "m3", 1002)} {
			if ok, err := s.InsertOwnerAsk(ctx, x); !ok || err != nil {
				t.Fatal(ok, err)
			}
		}
		if n, err := s.DeleteThreadOwnerAsks(ctx, a.ID, "t1"); n != 1 || err != nil {
			t.Fatalf("DeleteThreadOwnerAsks: %d %v", n, err)
		}
		// t3 has no thread row: an orphan. t2 has one and stays.
		if n, err := s.DeleteOrphanOwnerAsks(ctx, a.ID); n != 1 || err != nil {
			t.Fatalf("DeleteOrphanOwnerAsks: %d %v", n, err)
		}
		if _, err := s.GetOwnerAsk(ctx, a.ID, "ask_2"); err != nil {
			t.Fatalf("the ask of a thread still there went: %v", err)
		}
		for _, id := range []string{"ask_1", "ask_3"} {
			if _, err := s.GetOwnerAsk(ctx, a.ID, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("%s should be gone, got %v", id, err)
			}
		}
	})
}

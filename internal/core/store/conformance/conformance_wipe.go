package conformance

import (
	"context"
	"sort"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// threadIDWipe is the suite for what the wipe of thread ids of neither form reads and records
// (migration 0005, messaging.WipeThreadIDs), and for when the orphan sweep began (migration 0003):
// every thread id the store holds, of every account, each once, from a thread row, a message no
// thread row names and a change row, never a change row's empty id; the wipe pending after migrating
// and not after it ends.
func threadIDWipe(t *testing.T, newStore Factory) {
	t.Run("ThreadIDWipe", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wipe-a", DisplayName: "A", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wipe-b", DisplayName: "B", Algo: "p256"})
		for _, th := range []store.Thread{
			{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p"},
			{ID: "t2", AccountID: a.ID, ContactFpr: "sha256:p"},
			{ID: "t1", AccountID: b.ID, ContactFpr: "sha256:p"}, // the same id in another account
		} {
			th.CreatedAt, th.LastAt = 100, 100
			if err := s.InsertThread(ctx, th); err != nil {
				t.Fatal(err)
			}
		}
		for _, m := range []store.Message{
			{ID: "m1", AccountID: a.ID, ThreadID: "t1", MsgID: "m1"},           // named by its thread row too
			{ID: "m2", AccountID: a.ID, ThreadID: "t1", MsgID: "m2"},           // twice
			{ID: "m3", AccountID: a.ID, ThreadID: "Not.A.Thread", MsgID: "m3"}, // no thread row names it
		} {
			m.ContactFpr, m.Direction, m.Kind, m.Body, m.Status, m.Sender, m.CreatedAt = "sha256:p", "in", "text", "hi", "delivered", "human", 100
			if err := s.InsertMessage(ctx, m); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range []store.Change{
			{AccountID: a.ID, Kind: "message", ThreadID: "t1"},          // named by its thread row too
			{AccountID: b.ID, Kind: "message", ThreadID: "only/change"}, // only a change row names it
			{AccountID: b.ID, Kind: "request", ThreadID: ""},            // a contact's event: names no thread
		} {
			c.At = 100
			if _, err := s.AppendChange(ctx, c); err != nil {
				t.Fatal(err)
			}
		}

		ids, err := s.ListStoredThreadIDs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, id := range ids {
			got = append(got, id.AccountID+"/"+id.ThreadID)
		}
		sort.Strings(got)
		want := []string{a.ID + "/Not.A.Thread", a.ID + "/t1", a.ID + "/t2", b.ID + "/only/change", b.ID + "/t1"}
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("ListStoredThreadIDs = %v; want each (account, thread) once, the empty id skipped: %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ListStoredThreadIDs = %v; want %v", got, want)
			}
		}

		if pending, err := s.ThreadIDWipePending(ctx); err != nil || !pending {
			t.Fatalf("ThreadIDWipePending after migrating = %v, %v; want true", pending, err)
		}
		if err := s.EndThreadIDWipe(ctx); err != nil {
			t.Fatal(err)
		}
		if pending, err := s.ThreadIDWipePending(ctx); err != nil || pending {
			t.Fatalf("ThreadIDWipePending after EndThreadIDWipe = %v, %v; want false", pending, err)
		}
		if since, err := s.OrphanSweepSince(ctx); err != nil || since <= 0 {
			t.Fatalf("OrphanSweepSince = %d, %v; want the moment migration 0003 ran", since, err)
		}
	})
}

package messaging

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// sharedStores opens n handles on one store — n node processes sharing it — for each engine the
// test machine has: one SQLite file always, one Postgres database when HDTP_TEST_POSTGRES_DSN is
// set (the pre-push hook sets it).
func sharedStores(t *testing.T, n int) map[string][]store.Store {
	t.Helper()
	ctx := context.Background()
	out := map[string][]store.Store{}
	path := filepath.Join(t.TempDir(), "shared.db")
	for i := 0; i < n; i++ {
		st, err := store.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if i == 0 {
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
		}
		out["sqlite"] = append(out["sqlite"], st)
	}
	dsn := os.Getenv("HDTP_TEST_POSTGRES_DSN")
	if dsn == "" {
		return out
	}
	db := "hdtp_bus_" + strings.ToLower(strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+db)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)
	i := strings.LastIndex(dsn, "/")
	target := dsn[:i+1] + db
	if j := strings.Index(dsn[i+1:], "?"); j >= 0 {
		target += dsn[i+1:][j:]
	}
	for k := 0; k < n; k++ {
		st, err := store.OpenPostgres(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if k == 0 {
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
		}
		out["postgres"] = append(out["postgres"], st)
	}
	return out
}

func runBus(t *testing.T, b *Bus) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { b.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
}

func receive(t *testing.T, ch <-chan Event, within time.Duration) (Event, bool) {
	t.Helper()
	select {
	case e := <-ch:
		return e, true
	case <-time.After(within):
		return Event{}, false
	}
}

// An event published in one process reaches a subscriber in another that shares the store,
// carrying the change log's id; an event for another account does not reach an account's
// subscriber; and the publishing process's own subscriber hears its event once, at once, with
// the same id.
func TestAnEventCrossesToAnotherProcessOnTheStore(t *testing.T) {
	for engine, stores := range sharedStores(t, 2) {
		t.Run(engine, func(t *testing.T) {
			a, b := NewBus(stores[0]), NewBus(stores[1])
			runBus(t, a)
			runBus(t, b)
			time.Sleep(2 * PollInterval) // both readers past their starting id
			there, stopThere := b.Subscribe("acct-1")
			defer stopThere()
			here, stopHere := a.Subscribe("acct-1")
			defer stopHere()

			a.Publish(Event{Kind: EventCall, AccountID: "acct-2", ContactFpr: "sha256:x", Ref: "book_slot"})
			a.Publish(Event{Kind: EventMessage, AccountID: "acct-1", ThreadID: "t-1", ContactFpr: "sha256:c"})

			local, ok := receive(t, here, time.Second)
			if !ok || local.ThreadID != "t-1" || local.ID == 0 {
				t.Fatalf("the publishing process's own subscriber: %+v %v", local, ok)
			}
			remote, ok := receive(t, there, 5*time.Second)
			if !ok {
				t.Fatal("an event published in one process never reached a subscriber in the other")
			}
			if remote.ID != local.ID || remote.Kind != EventMessage || remote.ThreadID != "t-1" || remote.ContactFpr != "sha256:c" {
				t.Fatalf("the other process heard %+v, the publisher %+v", remote, local)
			}
			if again, ok := receive(t, there, 3*PollInterval); ok {
				t.Fatalf("an event for another account reached this account's subscriber, or one arrived twice: %+v", again)
			}
		})
	}
}

// Run passes over what this process published and has delivered already, and forgets the ids
// once it has read past them, so nothing is held.
func TestAProcessDoesNotHearItsOwnEventTwice(t *testing.T) {
	st := sharedStores(t, 1)["sqlite"][0]
	b := NewBus(st)
	b.running = true // as Run sets it; poll is driven by hand below
	ch, stop := b.Subscribe("")
	defer stop()
	b.Publish(Event{Kind: EventRequest, AccountID: "acct-1"})
	if _, ok := receive(t, ch, time.Second); !ok {
		t.Fatal("the publisher's subscriber heard nothing")
	}
	last := b.poll(context.Background(), 0)
	if e, ok := receive(t, ch, 100*time.Millisecond); ok {
		t.Fatalf("the reader delivered this process's own event again: %+v", e)
	}
	if last == 0 || len(b.mine) != 0 {
		t.Fatalf("read to %d, %d own ids still held", last, len(b.mine))
	}
}

// On Postgres the reader need not wait for its next poll: AppendChange notifies at commit, and
// WatchChanges, LISTENing on another connection, wakes.
func TestPostgresWakesAnotherProcessAtCommit(t *testing.T) {
	stores, ok := sharedStores(t, 2)["postgres"]
	if !ok {
		t.Skip("HDTP_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	woke := make(chan struct{}, 8)
	done := make(chan error, 1)
	go func() { done <- stores[1].WatchChanges(ctx, func() { woke <- struct{}{} }) }()
	time.Sleep(500 * time.Millisecond) // listening
	if _, err := stores[0].AppendChange(ctx, store.Change{AccountID: "a", Kind: "message", At: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-woke:
	case <-time.After(5 * time.Second):
		t.Fatal("a change appended in one process did not wake the other's watch")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("the watch ended with %v when its context did", err)
	}
}

// What an idle reader costs: one read of the log past its newest id, the query Run makes every
// PollInterval when nothing has changed.
func BenchmarkIdlePoll(b *testing.B) {
	st, err := store.OpenSQLite(filepath.Join(b.TempDir(), "idle.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		if _, err := st.AppendChange(ctx, store.Change{AccountID: "a", Kind: "message", At: int64(i)}); err != nil {
			b.Fatal(err)
		}
	}
	_, newest, _ := st.ChangeBounds(ctx)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.ChangesAfter(ctx, newest, pollPage); err != nil {
			b.Fatal(err)
		}
	}
}

// What another process appends after this process made its bus, and before its reader started,
// still arrives: the reader starts from the log's newest id when the bus was made. It started from
// the newest when it began reading, so an event published in that gap — a node already serving,
// its reader not yet running — was never delivered, and a surface invalidated in it stayed stale.
func TestAnEventPublishedBeforeTheReaderStartsIsDelivered(t *testing.T) {
	stores := sharedStores(t, 2)["sqlite"]
	a, b := NewBus(stores[0]), NewBus(stores[1])
	ch, stop := b.SubscribeSized("", 8)
	defer stop()
	a.Publish(Event{Kind: EventInvalidate, AccountID: "acct-1", ContactFpr: "sha256:x"})
	runBus(t, b)
	if e, ok := receive(t, ch, 5*time.Second); !ok || e.Kind != EventInvalidate {
		t.Fatalf("an event published before the reader started was not delivered: %+v %v", e, ok)
	}
}

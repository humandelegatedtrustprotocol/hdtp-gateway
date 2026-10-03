package audit_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/audit"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

func eventsOf(t *testing.T, st store.AuditStore) []audit.Event {
	t.Helper()
	rows, err := st.ListAuditEvents(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	events := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		events = append(events, audit.Event{
			Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	return events
}

func TestWriterExtendsPersistentChainAcrossRestart(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1756000000, 0)
	w := &audit.Writer{Sink: store.AuditAppender{St: st}, Now: func() time.Time { return clock }}
	for i := 0; i < 5; i++ {
		if err := w.Append(ctx, "acct", "contact", "sha256:x", "tools/call", "tool:send_message", "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	// "restart": a fresh writer must pick up the chain, not fork it
	w2 := &audit.Writer{Sink: store.AuditAppender{St: st}, Now: func() time.Time { return clock }}
	if err := w2.Append(ctx, "acct", "owner", "o1", "settings_update", "account:acct", "ok", "", ""); err != nil {
		t.Fatal(err)
	}
	events := eventsOf(t, st)
	if len(events) != 6 {
		t.Fatalf("rows: %d", len(events))
	}
	if idx, err := audit.Verify(events); err != nil {
		t.Fatalf("persistent chain broken at %d: %v", idx, err)
	}
	// filter by actor
	only, _ := st.ListAuditEvents(ctx, "o1")
	if len(only) != 1 || only[0].Action != "settings_update" {
		t.Fatalf("actor filter: %+v", only)
	}
}

// Several writers — one per node process, each its own store handle on one database — append at
// once, and the result is ONE chain: every row on the head before it, no seq written twice, no row
// lost (SPEC §11.4). A writer that carried the head in memory forked the chain here, or collided
// on seq and failed. On SQLite the handles share one file; on Postgres, one database.
func TestWritersInSeveralProcessesExtendOneChain(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "shared.db")
		var stores []store.AuditStore
		for i := 0; i < 3; i++ {
			st, err := store.OpenSQLite(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			if i == 0 {
				if err := st.Migrate(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			stores = append(stores, st)
		}
		appendTogether(t, stores)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("HDTP_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("HDTP_TEST_POSTGRES_DSN not set")
		}
		ctx := context.Background()
		const dbName = "hdtp_audit_writers"
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName)
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
			t.Fatal(err)
		}
		admin.Close(ctx)
		i := strings.LastIndex(dsn, "/")
		rest := dsn[i+1:]
		db := dsn[:i+1] + dbName
		if j := strings.Index(rest, "?"); j >= 0 {
			db += rest[j:]
		}
		var stores []store.AuditStore
		for i := 0; i < 3; i++ {
			st, err := store.OpenPostgres(ctx, db)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			if i == 0 {
				if err := st.Migrate(ctx); err != nil {
					t.Fatal(err)
				}
			}
			stores = append(stores, st)
		}
		appendTogether(t, stores)
	})
}

func appendTogether(t *testing.T, stores []store.AuditStore) {
	t.Helper()
	ctx := context.Background()
	const perWriter = 60
	var wg sync.WaitGroup
	errs := make(chan error, len(stores)*perWriter)
	for p, st := range stores {
		w := &audit.Writer{Sink: store.AuditAppender{St: st}}
		for g := 0; g < 2; g++ { // two goroutines per process, as a node has
			wg.Add(1)
			go func(p, g int) {
				defer wg.Done()
				for i := 0; i < perWriter/2; i++ {
					if err := w.Append(ctx, "", "system", "", "probe", fmt.Sprintf("p%d-g%d-%d", p, g, i), "ok", "", ""); err != nil {
						errs <- err
					}
				}
			}(p, g)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("an append beside other processes failed: %v", err)
	}
	events := eventsOf(t, stores[0])
	if want := len(stores) * perWriter; len(events) != want {
		t.Fatalf("%d rows on the chain, want %d", len(events), want)
	}
	if idx, err := audit.VerifyFrom(audit.GenesisHash, events); err != nil {
		t.Fatalf("the chain several processes wrote is broken at row %d: %v", idx, err)
	}
}

// What an append costs now that it reads the head in its own transaction (SQLite, one handle).
func BenchmarkWriterAppend(b *testing.B) {
	st, err := store.OpenSQLite(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		b.Fatal(err)
	}
	w := &audit.Writer{Sink: store.AuditAppender{St: st}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Append(ctx, "", "system", "", "probe", "bench", "ok", "", ""); err != nil {
			b.Fatal(err)
		}
	}
}

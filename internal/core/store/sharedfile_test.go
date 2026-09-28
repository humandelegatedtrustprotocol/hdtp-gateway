package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// Two node processes on one data dir are two connection pools on one SQLite file (SPEC §11.1): WAL
// lets their reads run beside a write, `busy_timeout` makes a writer wait for the other's lock
// rather than fail, and `_txlock=immediate` takes the write lock at BEGIN so a read-then-write
// transaction is never refused an upgrade. Every transaction from both commits.
func TestTwoStoresOnOneSQLiteFileCommitEveryWrite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shared.db")
	a, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	acct, err := a.CreateAccount(ctx, CreateAccountParams{Slug: "shared", DisplayName: "Shared", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const perStore, each = 4, 40
	var wg sync.WaitGroup
	failures := make(chan error, 2*perStore*each)
	for si, st := range []*SQLite{a, b} {
		for w := 0; w < perStore; w++ {
			wg.Add(1)
			go func(si, w int, st *SQLite) {
				defer wg.Done()
				for i := 0; i < each; i++ {
					err := st.Atomically(ctx, func(tx Store) error {
						if _, err := tx.GetAccountByID(ctx, acct.ID); err != nil {
							return err
						}
						return tx.InsertMessage(ctx, Message{ID: newID(), AccountID: acct.ID, ContactFpr: "sha256:p", MsgID: fmt.Sprintf("s%d-w%d-%d", si, w, i),
							ThreadID: "t", Direction: "in", Sender: "agent", Kind: "text", Body: "hi", Status: "delivered", CreatedAt: 1})
					})
					if err != nil {
						failures <- err
					}
				}
			}(si, w, st)
		}
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("a write from one of two stores on one file failed: %v", err)
	}
	msgs, err := b.ListMessagesByThread(ctx, acct.ID, "t")
	if err != nil {
		t.Fatal(err)
	}
	if want := 2 * perStore * each; len(msgs) != want {
		t.Fatalf("%d messages stored, want %d", len(msgs), want)
	}
}

// SchemaCurrent is how a serve that did not migrate — it shares the data dir with one that did —
// knows the schema is the one it serves: nil at this binary's version, an error naming the two
// versions when the schema is behind or ahead.
func TestSchemaCurrentNamesABehindOrAheadSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SchemaCurrent(ctx); err == nil || !strings.Contains(err.Error(), "has not been migrated") {
		t.Fatalf("an unmigrated store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.SchemaCurrent(ctx); err != nil {
		t.Fatalf("a migrated store: %v", err)
	}
	// A newer binary's migration, recorded the way goose records one (a test may write SQL).
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (99999, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := st.SchemaCurrent(ctx); err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("a schema a newer binary migrated: %v", err)
	}
}

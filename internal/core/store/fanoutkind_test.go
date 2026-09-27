package store_test

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/migrations"
)

// rotation_fanout.kind told a 1.x key rotation and a 1.x-ward renewal from a 2.0 move. The first
// two went with 1.x; what was left was one writer that always wrote 'move', no reader, and a
// default of 'rotation' in both engines. 0035 drops it.
//
// What the migration has to get right is the rows, not the column. A store that lived through 1.x
// can hold progress for a rotation nobody will finish, and once `kind` is gone nothing could tell
// such a row from a move's — so it goes first. The fixture stops at version 34 rather than
// building the table by hand, so it could not go stale when 0036 arrived.
//
// And 0036 did arrive: it renames the table to `move_fanout` and `new_fpr` to `leaf_kid`, under
// the rows. The fixture writes them by the names version 34 had, the store reads them back by
// the names it has now, and the move's progress has to come through both migrations whole.
func TestDroppingTheFanoutKindKeepsOnlyAMovesProgress(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lived-through-1x.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := fs.Sub(migrations.SQLite, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, raw, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 34); err != nil {
		t.Fatalf("migrating a fixture to version 34: %v", err)
	}
	// Raw SQL is a fixture's privilege; the code under test has none.
	for _, stmt := range []string{
		`INSERT INTO accounts (id, slug, display_name, algo, seal, status, created_at) VALUES ('acct', 'me', 'Me', 'ed25519', 'optional', 'active', 1)`,
		`INSERT INTO rotation_fanout (account_id, contact_fpr, new_fpr, status, attempts, last_error, updated_at, kind)
		 VALUES ('acct', 'sha256:moved-to', 'sha256:leaf2', 'done', 1, '', 10, 'move')`,
		`INSERT INTO rotation_fanout (account_id, contact_fpr, new_fpr, status, attempts, last_error, updated_at, kind)
		 VALUES ('acct', 'sha256:rotated-at', 'sha256:key2', 'pending', 3, 'unreachable', 11, 'rotation')`,
		`INSERT INTO rotation_fanout (account_id, contact_fpr, new_fpr, status, attempts, last_error, updated_at, kind)
		 VALUES ('acct', 'sha256:renewed-at', 'sha256:key3', 'pending', 1, '', 12, 'renewal_1x')`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	raw.Close()

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrating a store that lived through 1.x: %v", err)
	}
	rows, err := st.ListMoveFanout(ctx, "acct")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ContactFpr != "sha256:moved-to" || rows[0].LeafKid != "sha256:leaf2" || rows[0].Status != "done" {
		t.Fatalf("only the move's progress may survive, whole: %+v", rows)
	}
	// And the walk still records: the upsert no longer names a column that is not there.
	if err := st.UpsertMoveFanout(ctx, store.MoveFanout{AccountID: "acct", ContactFpr: "sha256:next", LeafKid: "sha256:leaf2", Status: "pending", Attempts: 1}); err != nil {
		t.Fatalf("recording progress after the migration: %v", err)
	}
	if rows, _ := st.ListMoveFanout(ctx, "acct"); len(rows) != 2 {
		t.Fatalf("progress was not recorded: %+v", rows)
	}
}

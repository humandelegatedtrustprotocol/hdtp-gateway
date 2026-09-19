package cli

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/migrations"
)

// stripKeys is what makes a restore data-only (PACT §9): another host's archive arrives and every
// key in it is refused. The archive's database is whatever age its source node was, so the store
// is migrated FIRST and stripped second — which is what lets the strip be two static sqlc queries
// instead of SQL assembled from a stranger's schema.
//
// The case that matters most is the old archive. Before migration 0031 `accounts` carried
// `prev_key_sealed`, which could hold a sealed private key from a 1.x rotation that was in flight.
// "Keys never travel" has to be true of that file too, and here it is true because migrating
// destroys the column rather than because anything remembered to name it.
//
// The fixture is a real one: goose drives a fresh database to EXACTLY version 30, which is what a
// node from before 0031 would have archived. An earlier draft migrated fully and wound the version
// table back by hand, and broke the day migration 0032 landed — it had quietly assumed 0031 would
// always be the newest. Stopping at a version cannot go stale that way.
func TestStripKeysMigratesFirstSoAnOldArchiveLosesItsRetiringKeyToo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restored.db")

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
	if _, err := p.UpTo(ctx, 30); err != nil {
		t.Fatalf("migrating a fixture to version 30: %v", err)
	}
	// Raw SQL is a fixture's privilege; the code under test has none. An account with a live key
	// and a retiring one, and a leaf the host is currently serving.
	for _, stmt := range []string{
		`INSERT INTO accounts (id, slug, display_name, algo, fingerprint, key_sealed, seal, status, created_at, prev_fingerprint, prev_key_sealed, grace_until)
		 VALUES ('acct', 'old', 'Old', 'ed25519', 'sha256:k', x'AC', 'optional', 'active', 1, 'sha256:retiring', x'C0FFEE', 99)`,
		`INSERT INTO leaves (account_id, kid, leaf, key_sealed, not_before, not_after, state, endpoint, created_at)
		 VALUES ('acct', 'sha256:cur', x'1E', x'1EAF', 1, 9, 'current', 'https://a.example/mcp', 1)`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	raw.Close()

	if err := stripKeys(path); err != nil {
		t.Fatalf("an archive from before 0031 failed to restore: %v", err)
	}

	raw, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var cols int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name IN ('prev_key_sealed','prev_fingerprint','grace_until')`).Scan(&cols); err != nil {
		t.Fatal(err)
	}
	if cols != 0 {
		t.Fatalf("%d rotation column(s) survived the restore — and one of them held a private key", cols)
	}

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if k, _ := st.GetAccountSealedKey(ctx, "acct"); len(k) != 0 {
		t.Fatalf("the account key travelled: %q", k)
	}
	leaves, err := st.ListLeaves(ctx, "acct")
	if err != nil || len(leaves) != 1 {
		t.Fatalf("the ledger row should survive the strip: %d rows, %v", len(leaves), err)
	}
	if len(leaves[0].KeySealed) != 0 || leaves[0].State != "former" {
		t.Fatalf("the leaf kept its key or its standing: key=%d bytes, state=%q", len(leaves[0].KeySealed), leaves[0].State)
	}
}

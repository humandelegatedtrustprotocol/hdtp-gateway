package cli

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
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
func TestStripKeysMigratesFirstSoAnOldArchiveLosesItsRetiringKeyToo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "restored.db")

	// A store at the current schema, holding an account key and a live leaf key.
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "old", DisplayName: "Old", Algo: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountKey(ctx, a.ID, "sha256:k", []byte("account-key")); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:cur", Leaf: []byte("l"), KeySealed: []byte("leaf-key"),
		NotBefore: 1, NotAfter: 9, State: "current", Endpoint: "https://a.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Wind it back to what a node from before 0031 would have archived: the three rotation
	// columns present, a retiring key in one of them, and goose believing 0030 is the newest
	// migration applied. Raw SQL is a fixture's privilege; the code under test has none.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`ALTER TABLE accounts ADD COLUMN prev_fingerprint TEXT`,
		`ALTER TABLE accounts ADD COLUMN prev_key_sealed BLOB`,
		`ALTER TABLE accounts ADD COLUMN grace_until INTEGER NOT NULL DEFAULT 0`,
		`UPDATE accounts SET prev_key_sealed = x'C0FFEE', prev_fingerprint = 'sha256:retiring', grace_until = 99`,
		`DELETE FROM goose_db_version WHERE version_id >= 31`,
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

	st, err = store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if k, _ := st.GetAccountSealedKey(ctx, a.ID); len(k) != 0 {
		t.Fatalf("the account key travelled: %q", k)
	}
	leaves, err := st.ListLeaves(ctx, a.ID)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("the ledger row should survive the strip: %d rows, %v", len(leaves), err)
	}
	if len(leaves[0].KeySealed) != 0 || leaves[0].State != "former" {
		t.Fatalf("the leaf kept its key or its standing: key=%d bytes, state=%q", len(leaves[0].KeySealed), leaves[0].State)
	}
}

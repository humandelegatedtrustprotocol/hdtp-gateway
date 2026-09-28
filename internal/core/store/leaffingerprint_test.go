package store_test

// Migration 0046 gives every pin the fingerprint of its leaf's key (`leaf_fingerprint`), which
// PinCandidates finds a small form's pin by. There is no branch for a row without it: a row that
// holds a leaf and no fingerprint is a contact whose small-form calls find no pin. So two things
// are held here. Migrate fills every row held before 0046, on both engines, to pact-identity's
// Fingerprint (fillLeafFingerprints). And every statement that writes `leaf` writes
// `leaf_fingerprint` with it.

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/migrations"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// The rows a node held before 0046: a pin with a leaf, a row with a key and no leaf (a request),
// and a row whose leaf is empty.
var before0046 = []string{
	`INSERT INTO accounts (id, slug, display_name, algo, seal, status, created_at) VALUES ('acct', 'me', 'Me', 'ed25519', 'optional', 'active', 1)`,
	`INSERT INTO contacts (id, account_id, fingerprint, spki, status, created_at, endpoint, leaf) VALUES ('c-pin', 'acct', 'sha256:a', $1, 'active', 1, 'https://a.example/mcp', $2)`,
	`INSERT INTO contacts (id, account_id, fingerprint, spki, status, created_at) VALUES ('c-request', 'acct', 'sha256:b', $1, 'pending_in', 2)`,
	`INSERT INTO contacts (id, account_id, fingerprint, spki, status, created_at, leaf) VALUES ('c-empty', 'acct', 'sha256:c', $1, 'active', 3, $2)`,
}

var (
	pinKey  = []byte("the pinned leaf's key, as DER would be")
	pinLeaf = []byte("a leaf")
)

// argsFor gives each fixture statement the arguments it names.
func argsFor(stmt string) []any {
	switch {
	case strings.Contains(stmt, "'c-pin'"):
		return []any{pinKey, pinLeaf}
	case strings.Contains(stmt, "'c-request'"):
		return []any{pinKey}
	case strings.Contains(stmt, "'c-empty'"):
		return []any{pinKey, []byte{}}
	}
	return nil
}

func checkFilled(t *testing.T, fingerprints map[string]sql.NullString) {
	t.Helper()
	want := map[string]sql.NullString{
		"c-pin":     {String: pactidentity.Fingerprint(pinKey), Valid: true},
		"c-request": {},
		"c-empty":   {},
	}
	for id, w := range want {
		if got := fingerprints[id]; got != w {
			t.Errorf("%s: leaf_fingerprint %+v, want %+v", id, got, w)
		}
	}
}

func TestMigration0046FillsEveryPinsFingerprintOnSQLite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "before-0046.db")
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
	if _, err := p.UpTo(ctx, 45); err != nil {
		t.Fatalf("migrating a fixture to version 45: %v", err)
	}
	// Raw SQL is a fixture's privilege; the code under test has none.
	for _, stmt := range before0046 {
		args := argsFor(stmt)
		stmt = regexp.MustCompile(`\$\d`).ReplaceAllString(stmt, "?")
		if _, err := raw.ExecContext(ctx, stmt, args...); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	raw.Close()

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st.Close()

	raw, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.QueryContext(ctx, `SELECT id, leaf_fingerprint FROM contacts`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]sql.NullString{}
	for rows.Next() {
		var id string
		var f sql.NullString
		if err := rows.Scan(&id, &f); err != nil {
			t.Fatal(err)
		}
		got[id] = f
	}
	checkFilled(t, got)
}

func TestMigration0046FillsEveryPinsFingerprintOnPostgres(t *testing.T) {
	dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PACT_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	const dbName = "pact_before_0046"
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)
	conn, err := pgx.Connect(ctx, rewriteDB(dsn, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	db := stdlib.OpenDB(*conn.Config())
	defer db.Close()
	sub, err := fs.Sub(migrations.Postgres, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 45); err != nil {
		t.Fatalf("migrating a fixture to version 45: %v", err)
	}
	for _, stmt := range before0046 {
		if _, err := conn.Exec(ctx, stmt, argsFor(stmt)...); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	st, err := store.OpenPostgres(ctx, rewriteDB(dsn, dbName))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st.Close()

	rows, err := conn.Query(ctx, `SELECT id, leaf_fingerprint FROM contacts`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]sql.NullString{}
	for rows.Next() {
		var id string
		var f sql.NullString
		if err := rows.Scan(&id, &f); err != nil {
			t.Fatal(err)
		}
		got[id] = f
	}
	checkFilled(t, got)
}

// Every statement that writes `leaf` into contacts writes `leaf_fingerprint` beside it, in both
// dialects: an INSERT that lists `leaf` lists `leaf_fingerprint`, an UPDATE that sets one sets the
// other. The control: the statements are found (five writers in each dialect today).
func TestEveryStatementThatWritesALeafWritesItsFingerprint(t *testing.T) {
	header := regexp.MustCompile(`(?m)^-- name: ([A-Za-z]+) :[a-z]+\s*$`)
	insertLeaf := regexp.MustCompile(`(?is)INSERT INTO contacts\s*\(([^)]*)\)`)
	setLeaf := regexp.MustCompile(`(?is)UPDATE contacts SET (.*?)\bWHERE\b`)
	for _, dialect := range []string{"sqlite", "postgres"} {
		dir := filepath.Join("..", "..", "..", "queries", dialect)
		files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
		if err != nil {
			t.Fatal(err)
		}
		writers := 0
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			src := string(b)
			locs := header.FindAllStringSubmatchIndex(src, -1)
			for i, loc := range locs {
				end := len(src)
				if i+1 < len(locs) {
					end = locs[i+1][0]
				}
				name, body := src[loc[2]:loc[3]], src[loc[1]:end]
				var written []string
				if m := insertLeaf.FindStringSubmatch(body); m != nil {
					written = strings.Split(m[1], ",")
				} else if m := setLeaf.FindStringSubmatch(body); m != nil {
					for _, a := range strings.Split(m[1], ",") {
						written = append(written, strings.SplitN(a, "=", 2)[0])
					}
				}
				has := map[string]bool{}
				for _, c := range written {
					has[strings.TrimSpace(c)] = true
				}
				if !has["leaf"] {
					continue
				}
				writers++
				if !has["leaf_fingerprint"] {
					t.Errorf("%s: %s writes contacts.leaf and not leaf_fingerprint", dialect, name)
				}
			}
		}
		if writers < 5 {
			t.Fatalf("%s: %d statements write a contact's leaf; this guard is checking nothing", dialect, writers)
		}
	}
}

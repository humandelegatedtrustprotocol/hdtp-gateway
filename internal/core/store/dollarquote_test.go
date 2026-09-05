package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// GO-2026-5004 was SQL injection in pgx via placeholder confusion with
// DOLLAR-QUOTED string literals: pgx's client-side sanitizer interpolates
// arguments into the SQL text, and a `$$…$$` literal could confuse its
// placeholder scanner into substituting an argument where it should not.
//
// This node was not exposed, but only because two things never coincided. The SQL
// that carries arguments — everything in queries/ and the generated pgdb code —
// uses `$1..$N` and contains no dollar-quoted literal. The SQL that DOES contain
// one (two migrations, `CREATE FUNCTION … AS $$`) runs through goose over
// database/sql with no arguments at all, so there is nothing to substitute.
//
// That is an incidental property, and safety by coincidence expires. It matters
// because pgx reads `default_query_exec_mode` from the CONNECTION STRING
// (conn.go:192) and `postgres_dsn` is owner-supplied: an owner behind PgBouncer in
// transaction-pooling mode has a documented reason to select the simple protocol,
// which routes every runtime query through the client-side sanitizer. The
// dependency is patched, but the next dollar-quoted literal added to an
// argument-bearing query would put this node back on the wrong side of that class
// of bug. So the property is enforced here rather than left to luck.
//
// Migrations are deliberately exempt: they take no arguments.
func TestArgumentBearingSQLHasNoDollarQuotedLiterals(t *testing.T) {
	root := repoRootForSQL(t)
	// A dollar-quoted literal is $$ or $tag$. A placeholder is $1..$N — the digits
	// are what tell them apart.
	dollarQuote := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)?\$`)

	scanned := 0
	for _, dir := range []string{"queries", filepath.Join("internal", "core", "store", "pgdb")} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !strings.HasSuffix(p, ".sql") && !strings.HasSuffix(p, ".sql.go") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			scanned++
			rel, _ := filepath.Rel(root, p)
			for _, m := range dollarQuote.FindAllString(string(b), -1) {
				t.Errorf("%s contains the dollar-quoted literal %q. This SQL is executed "+
					"WITH ARGUMENTS, so on the simple protocol it is interpolated "+
					"client-side — which is exactly the shape GO-2026-5004 exploited. Use a "+
					"standard quoted literal, or move it to a migration, which takes no "+
					"arguments.", rel, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned == 0 {
		t.Fatal("no SQL scanned — this lint is looking in the wrong place and would " +
			"never catch anything")
	}
}

func repoRootForSQL(t *testing.T) string {
	t.Helper()
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		d = filepath.Dir(d)
	}
	t.Fatal("no go.mod above the test's working directory")
	return ""
}

package integrationtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// handWritten are generated-package functions that are not queries at all, so
// no .sql file describes them.
var handWritten = map[string]bool{"WithTx": true}

// CONTRIBUTING says it plainly: sqlc is not installed, and the code it would
// generate is hand-written to match queries/. Nothing enforced the "to match"
// half, and it had already drifted — UpdateContactPetname existed only in the
// Go, and InsertMessage's query was a column behind the code that runs. Both
// are the kind of gap that looks harmless until someone regenerates for real,
// or reads queries/ to understand what the store does.
func TestQueriesMatchTheHandWrittenCode(t *testing.T) {
	root := repoRoot(t)
	for _, d := range []struct{ queries, pkg, ph string }{
		{"queries/sqlite", "internal/core/store/sqlitedb", "?"},
		{"queries/postgres", "internal/core/store/pgdb", "$"},
	} {
		fromSQL := readQueries(t, filepath.Join(root, d.queries))
		fromGo := readGenerated(t, filepath.Join(root, d.pkg))

		for name := range fromGo {
			if handWritten[name] {
				continue
			}
			if _, ok := fromSQL[name]; !ok {
				t.Errorf("%s: %s is implemented in Go with no query in %s. Add it, "+
					"or add it to handWritten if it is not a query.", d.pkg, name, d.queries)
			}
		}
		for name := range fromSQL {
			if _, ok := fromGo[name]; !ok {
				t.Errorf("%s: %s has a query with no Go implementation.", d.queries, name)
			}
		}
		for name, sql := range fromSQL {
			gen, ok := fromGo[name]
			if !ok {
				continue
			}
			if want, got := normalizeSQL(sql), expandStar(normalizeSQL(gen), normalizeSQL(sql)); want != got {
				t.Errorf("%s: %s has drifted.\n  queries/: %s\n  code:     %s",
					d.queries, name, want, got)
			}
		}
		if len(fromSQL) < 50 {
			t.Fatalf("%s: only %d queries read; this lint is checking nothing", d.queries, len(fromSQL))
		}
		t.Logf("%s: %d queries match", d.queries, len(fromSQL))
	}
}

var queryHeader = regexp.MustCompile(`(?m)^-- name: ([A-Za-z]+) :[a-z]+\s*$`)

func readQueries(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		locs := queryHeader.FindAllStringSubmatchIndex(src, -1)
		for i, loc := range locs {
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			out[src[loc[2]:loc[3]]] = src[loc[1]:end]
		}
	}
	return out
}

var genConst = regexp.MustCompile("(?s)= `-- name: ([A-Za-z]+) :[a-z]+\n(.*?)\n`")

func readGenerated(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range genConst.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = m[2]
		}
		// Functions with no const are still implementations worth naming.
		for _, m := range regexp.MustCompile(`func \(q \*Queries\) ([A-Za-z]+)\(`).FindAllStringSubmatch(string(b), -1) {
			if _, ok := out[m[1]]; !ok {
				out[m[1]] = ""
			}
		}
	}
	return out
}

// normalizeSQL drops comments and collapses whitespace so formatting is not
// mistaken for drift.
func normalizeSQL(s string) string {
	var kept []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "--") {
			kept = append(kept, t)
		}
	}
	return strings.TrimSuffix(strings.Join(strings.Fields(strings.Join(kept, " ")), " "), ";")
}

// expandStar puts `SELECT *` back where sqlc would have written the column list,
// so the two forms of the same query compare equal.
func expandStar(gen, want string) string {
	if !strings.HasPrefix(want, "SELECT * ") || !strings.HasPrefix(gen, "SELECT ") {
		return gen
	}
	if i := strings.Index(gen, " FROM "); i > 0 {
		return "SELECT *" + gen[i:]
	}
	return gen
}

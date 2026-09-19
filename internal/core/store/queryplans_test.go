package store_test

// Every statement the store can run is asked how it would be answered, on both engines, and a
// statement that would read the whole of a table that GROWS — or sort what it read from one —
// fails the build unless it is listed below with the reason that is acceptable.
//
// It reads the statements from the code sqlc generated, so a new query is covered the day it is
// written, and it asks the real planner against the real migrated schema, so an index that a
// later migration forgets to carry across a table rebuild is caught as well. An entry in a
// justified list that no longer describes its statement fails too: the list cannot rot.
//
// What this proves is that an index EXISTS for each statement. What each one is worth at a
// million rows is measured in scale_test.go.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	_ "modernc.org/sqlite"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// growing is every table whose size follows use rather than configuration. The others hold a row
// per owner, account, token, passkey, catalog or integration, or a short per-account ledger
// (leaves, tombstones, former and pending addresses), and reading all of one is reading a handful.
var growing = map[string]bool{
	"messages": true, "threads": true, "contacts": true, "audit_events": true, "blobs": true,
	"idempotency": true, "invites": true, "pending_requests": true, "move_fanout": true, "sessions": true,
}

// Justified on BOTH engines, for the same reason on each.
var justified = map[string]string{
	"ListAuditEvents":       "verifying, exporting and archiving a hash chain IS reading the whole chain, in order",
	"ListAuditEventsPage":   "a bounded walk of the chain from its newest end; the node's own rows match every account filter, so it stops within a page or so whatever the account",
	"LastAuditEvent":        "one row, from the end of the primary key",
	"DeleteExpiredSessions": "reads the owner sessions, which this statement is what keeps few: one per sign-in, gone within the hour of expiring",
}

// SQLite only.
var justifiedSQLite = map[string]string{
	"DeleteOwner":             "the foreign-key check on removing an owner, which a person does by hand; sessions are bounded by the hourly sweep",
	"ListOpenPendingRequests": "sorts the OPEN requests of one account, found through an index; an open request expires within minutes",
}

// Postgres only.
var justifiedPostgres = map[string]string{
	"ListOpenPendingRequests": "sorts the OPEN requests of one account, found through an index; an open request expires within minutes",
}

type generatedQuery struct{ Name, SQL string }

// generatedQueries reads the statements out of the constants sqlc wrote, which is the text the
// driver is handed.
func generatedQueries(t *testing.T, dir string) []generatedQuery {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.sql.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no generated query files under %s (%v)", dir, err)
	}
	head := regexp.MustCompile(`^-- name: (\w+) :\w+`)
	var out []generatedQuery
	for _, f := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Values) != 1 {
				return true
			}
			lit, ok := spec.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if m := head.FindStringSubmatch(text); m != nil {
				out = append(out, generatedQuery{Name: m[1], SQL: text})
			}
			return true
		})
	}
	if len(out) < 100 {
		t.Fatalf("read only %d statements from %s: the reader is broken, not the store", len(out), dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var (
	aliasOf     = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+(\w+)\s+(?:AS\s+)?(\w+)\b`)
	notAnAlias  = regexp.MustCompile(`(?i)^(WHERE|ORDER|SET|ON|USING|GROUP|LIMIT|LEFT|INNER|JOIN|RETURNING|AS)$`)
	sqliteScan  = regexp.MustCompile(`^SCAN (\w+)$`)
	sqliteWalk  = regexp.MustCompile(`^SCAN (\w+) USING (?:COVERING )?INDEX (\w+)$`)
	numberedArg = regexp.MustCompile(`\?(\d+)`)
)

// tableFor maps a name in a plan back to its table: SQLite prints an alias where one was given.
func tableFor(sqlText, name string) string {
	for _, m := range aliasOf.FindAllStringSubmatch(sqlText, -1) {
		if m[2] == name && !notAnAlias.MatchString(m[2]) {
			return m[1]
		}
	}
	return name
}

func sqliteArgs(sqlText string) []any {
	n := 0
	for _, m := range numberedArg.FindAllStringSubmatch(sqlText, -1) {
		if k, _ := strconv.Atoi(m[1]); k > n {
			n = k
		}
	}
	if n == 0 {
		n = strings.Count(sqlText, "?")
	}
	return make([]any, n)
}

func TestEveryQueryHasAPlan(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "plans.db")
		st, err := store.OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		st.Close()
		// Foreign keys ON, as the store opens it: the checks they add are part of a statement's plan.
		db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		// A partial index holds only the rows a statement wants, so walking all of it is the design.
		partial := names(t, func() (rowsLike, error) {
			return db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'index' AND sql LIKE '% WHERE %'")
		})

		found := map[string][]string{}
		for _, q := range generatedQueries(t, "sqlitedb") {
			rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q.SQL, sqliteArgs(q.SQL)...)
			if err != nil {
				t.Errorf("%s cannot be explained, so nothing is known about it: %v", q.Name, err)
				continue
			}
			var touchesGrowing, sorts bool
			var why []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				for _, word := range strings.Fields(detail) {
					if growing[tableFor(q.SQL, word)] {
						touchesGrowing = true
					}
				}
				if m := sqliteScan.FindStringSubmatch(detail); m != nil && growing[tableFor(q.SQL, m[1])] {
					why = append(why, "reads all of "+tableFor(q.SQL, m[1]))
				}
				if m := sqliteWalk.FindStringSubmatch(detail); m != nil && growing[tableFor(q.SQL, m[1])] && !partial[m[2]] {
					why = append(why, "walks all of "+m[2]+" on "+tableFor(q.SQL, m[1]))
				}
				if strings.Contains(detail, "USE TEMP B-TREE FOR ORDER BY") {
					sorts = true
				}
			}
			rows.Close()
			if sorts && touchesGrowing {
				why = append(why, "sorts what it read")
			}
			if len(why) > 0 {
				found[q.Name] = why
			}
		}
		settle(t, "sqlite", found, justified, justifiedSQLite)
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("PACT_TEST_POSTGRES_DSN not set")
		}
		ctx := context.Background()
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		// A throwaway database on the test server, as the conformance suite makes them.
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS pact_plans")
		if _, err := admin.Exec(ctx, "CREATE DATABASE pact_plans"); err != nil {
			t.Fatal(err)
		}
		admin.Close(ctx)
		st, err := store.OpenPostgres(ctx, rewriteDB(dsn, "pact_plans"))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		st.Close()
		conn, err := pgx.Connect(ctx, rewriteDB(dsn, "pact_plans"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		// On an empty table the planner prefers a sequential scan to any index. Forbidding one is how
		// the question becomes "is there an index this statement could use".
		// Sorts and bitmap scans likewise: an ordered index is preferred to either only when they are
		// priced out, and whether one EXISTS is the question.
		for _, off := range []string{"enable_seqscan", "enable_sort", "enable_bitmapscan"} {
			if _, err := conn.Exec(ctx, "SET "+off+" = off"); err != nil {
				t.Fatal(err)
			}
		}
		partial := names(t, func() (rowsLike, error) {
			return conn.Query(ctx, "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE i.indpred IS NOT NULL")
		})

		found := map[string][]string{}
		for _, q := range generatedQueries(t, "pgdb") {
			// GENERIC_PLAN plans a statement with its placeholders still in it, which is what the node
			// prepares. It goes down the wire as it is: pgx would otherwise want a value for each.
			res, err := conn.PgConn().Exec(ctx, "EXPLAIN (GENERIC_PLAN, FORMAT JSON) "+q.SQL).ReadAll()
			if err != nil || len(res) != 1 || len(res[0].Rows) != 1 {
				t.Errorf("%s cannot be explained, so nothing is known about it: %v", q.Name, err)
				continue
			}
			raw := res[0].Rows[0][0]
			var plans []struct {
				Plan map[string]any `json:"Plan"`
			}
			if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
				t.Fatalf("%s: a plan that does not parse: %v", q.Name, err)
			}
			var why []string
			var touchesGrowing, sorts bool
			var walk func(n map[string]any)
			walk = func(n map[string]any) {
				kind, _ := n["Node Type"].(string)
				rel, _ := n["Relation Name"].(string)
				if growing[rel] {
					touchesGrowing = true
					_, conditioned := n["Index Cond"]
					switch {
					case kind == "Seq Scan":
						why = append(why, "reads all of "+rel)
					case (kind == "Index Scan" || kind == "Index Only Scan") && !conditioned && !partial[fmt.Sprint(n["Index Name"])]:
						why = append(why, fmt.Sprintf("walks all of %v on %s", n["Index Name"], rel))
					}
				}
				if kind == "Sort" {
					sorts = true
				}
				children, _ := n["Plans"].([]any)
				for _, c := range children {
					if m, ok := c.(map[string]any); ok {
						walk(m)
					}
				}
			}
			walk(plans[0].Plan)
			if sorts && touchesGrowing {
				why = append(why, "sorts what it read")
			}
			if len(why) > 0 {
				found[q.Name] = why
			}
		}
		settle(t, "postgres", found, justified, justifiedPostgres)
	})
}

// rowsLike is what both drivers' result sets have in common.
type rowsLike interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// names reads a one-column result into a set. The pgx and database/sql result sets close
// differently, so the caller's query is drained to its end rather than closed here.
func names(t *testing.T, query func() (rowsLike, error)) map[string]bool {
	t.Helper()
	rows, err := query()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// settle compares what the planner said with what is justified, in both directions.
func settle(t *testing.T, engine string, found map[string][]string, lists ...map[string]string) {
	t.Helper()
	allowed := map[string]string{}
	for _, l := range lists {
		for name, why := range l {
			allowed[name] = why
		}
	}
	var names []string
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := allowed[name]; !ok {
			t.Errorf("%s: %s %s. Give it an index (a migration on BOTH engines), or justify it in this file with the reason a reader would accept.",
				engine, name, strings.Join(found[name], ", "))
		}
	}
	for name, why := range allowed {
		if _, ok := found[name]; !ok {
			t.Errorf("%s: %s is justified (%s) and the planner no longer says it needs to be: the list is stale", engine, name, why)
		}
	}
}

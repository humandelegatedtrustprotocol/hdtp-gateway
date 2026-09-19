package integrationtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The owner's rule, 2026-09-19: "use orm/sqlc Only to deal with db no queries to be written without
// it unless its a test case." It was made about one line —
//
//	db.ExecContext(ctx, "UPDATE "+quoteIdent(table)+" SET "+quoteIdent(col)+" = NULL")
//
// — and a rule that lives in the memory of whoever was told it lasts as long as they are the one
// typing. This is the rule as a build failure.
//
// Three checks over every production Go file (tests are exempt, as the rule says; the generated
// packages ARE sqlc and are skipped):
//
//  1. `database/sql`, a driver, or goose is imported only inside `internal/core/store`. A package
//     that cannot name a connection cannot run a statement on one. Callers that only wanted to ask
//     "was it not found?" have `store.ErrNotFound`.
//  2. No string literal anywhere is a SQL statement. This is the check that catches a statement
//     assembled in one place and executed in another, which a look at call sites would miss.
//  3. Inside the store's own hand-written files — the one place that may hold a connection — no
//     call runs a statement directly (`Exec`, `Query`, `QueryRow`, `Prepare` and their `Context`
//     forms). Check 2 cannot see the line the rule was made about: `"UPDATE "+table+" SET "+…`
//     has no single literal that reads as a statement. This sees the call instead.
//  4. The single exception is named, located, and COUNTED: `SQLite.Snapshot`'s `VACUUM INTO ?`,
//     which sqlc's SQLite grammar rejects and which is storage maintenance, not a query. If it
//     moves or multiplies the test fails, so the list cannot quietly grow a second entry.
func TestNoHandWrittenSQLOutsideTheStore(t *testing.T) {
	root := repoRoot(t)
	const storeDir = "internal/core/store/"
	generated := []string{storeDir + "sqlitedb/", storeDir + "pgdb/"}
	dbImports := []string{"database/sql", "github.com/jackc/pgx/", "modernc.org/sqlite", "github.com/pressly/goose/", "github.com/mattn/go-sqlite3", "github.com/lib/pq"}
	statement := regexp.MustCompile(`(?is)^\s*(select\s|insert\s+into\s|update\s+\S+\s+set\s|delete\s+from\s|create\s+(table|index|unique\s+index|trigger)\s|alter\s+table\s|drop\s+(table|index|trigger)\s|vacuum\b|pragma\s|replace\s+into\s|with\s+\w+\s+as\s*\()`)

	runsAStatement := map[string]bool{
		"Exec": true, "ExecContext": true, "Query": true, "QueryContext": true,
		"QueryRow": true, "QueryRowContext": true, "Prepare": true, "PrepareContext": true,
	}
	type exception struct{ file, fn, literal string }
	allowed := exception{file: storeDir + "sqlite.go", fn: "Snapshot", literal: "VACUUM INTO ?"}
	allowedSeen := 0
	var files, literals int

	for _, dir := range []string{"internal", "cmd", "migrations"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, g := range generated {
				if strings.HasPrefix(rel, g) {
					return nil
				}
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Fatalf("%s does not parse: %v", rel, perr)
			}
			files++

			// 1. who may name a database at all
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				for _, db := range dbImports {
					if (p == db || strings.HasPrefix(p, db)) && !strings.HasPrefix(rel, storeDir) {
						t.Errorf("%s imports %q. Database access goes through the Store interface and sqlc "+
							"(queries/*.sql, `make sqlc`); nothing outside %s names a connection. If it only "+
							"needs to know a row was absent, that is store.ErrNotFound.", rel, p, storeDir)
					}
				}
			}

			// 2, 3 and 4. no statement in a string, wherever it is headed; and in the store, no
			// statement run by hand
			var fn string
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.FuncDecl:
					fn = x.Name.Name
				case *ast.CallExpr:
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok || !strings.HasPrefix(rel, storeDir) || !runsAStatement[sel.Sel.Name] || len(x.Args) == 0 {
						return true
					}
					if rel == allowed.file && fn == allowed.fn {
						return true // counted below, by its literal
					}
					t.Errorf("%s:%d (in %s) runs a statement by hand: .%s(…). In the store a statement is a generated "+
						"method on `s.q`; write it in queries/*.sql and run `make sqlc`.", rel, fset.Position(x.Pos()).Line, fn, sel.Sel.Name)
				case *ast.BasicLit:
					if x.Kind != token.STRING {
						return true
					}
					literals++
					val, uerr := strconv.Unquote(x.Value)
					if uerr != nil || !statement.MatchString(val) {
						return true
					}
					if rel == allowed.file && fn == allowed.fn && val == allowed.literal {
						allowedSeen++
						return true
					}
					t.Errorf("%s:%d (in %s) holds a SQL statement in a string: %q. Write it in queries/{sqlite,postgres}/*.sql, "+
						"run `make sqlc`, and call the generated method through the Store interface. The one "+
						"exception is %s's %q, and it is not a precedent.",
						rel, fset.Position(x.Pos()).Line, fn, val, allowed.fn, allowed.literal)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if allowedSeen != 1 {
		t.Errorf("the one permitted hand-written statement — %q in %s (%s) — was found %d time(s). "+
			"Exactly one: if it moved, move this entry with it and say why; if there are two, one of them is not the exception.",
			allowed.literal, allowed.file, allowed.fn, allowedSeen)
	}
	if files < 100 || literals < 1000 {
		t.Fatalf("read %d files and %d string literals: this guard is looking at nothing", files, literals)
	}
	t.Logf("read %d production files and %d string literals", files, literals)
}

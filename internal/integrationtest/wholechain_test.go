package integrationtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// `Store.ListAuditEvents` returns the whole audit chain, because verifying a hash chain IS reading
// all of it, in order. Anything that wants the trail to SHOW somebody wants a page
// (`ListAuditEventsPage`), and the difference is every row the node has ever written: the owner
// MCP's `audit_query` and the dashboard's recent activity both asked for the chain and kept the
// last few rows, on every call, and a plan check cannot see that — the statement is correct, and
// the caller is what is wrong. So the callers are listed, with why each reads everything.
func TestOnlyWhatVerifiesTheChainReadsAllOfIt(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]string{
		"internal/core/audit/archive.go":         "verify, export, archive and repair: each walks the chain link by link",
		"internal/core/auditstore/auditstore.go": "the adapter that hands the store to internal/core/audit",
		"internal/core/audit/departed.go":        "an identity's archive verifies the chain before it moves rows out of it, and finds the rows that name the identity",
		"internal/cli/auditcmd.go":               "`hdtp-gateway audit`, the offline commands over the whole chain",
	}
	found := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// The store's own engines call the generated query of the same name; that is the
			// method's body, not a second reader.
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ListAuditEvents" && !strings.HasPrefix(rel, "internal/core/store/") {
				found[rel] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var unlisted []string
	for rel := range found {
		if _, ok := allowed[rel]; !ok {
			unlisted = append(unlisted, rel)
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) > 0 {
		t.Errorf("these read the WHOLE audit chain: %s.\nTo show the trail, ask for a page (Store.ListAuditEventsPage). "+
			"To walk the chain, list the file here with why it must read all of it.", strings.Join(unlisted, ", "))
	}
	for rel, why := range allowed {
		if !found[rel] {
			t.Errorf("%s is listed as reading the whole chain (%s) and no longer does: the list is stale", rel, why)
		}
	}
	if len(found) == 0 {
		t.Fatal("found no reader of the chain at all: the walk is broken, not the code")
	}
}

// The two deletes on the audit chain (SPEC §11.4) are safe only behind the archive that writes the
// rows out first, and the prune guard cannot see a file: it admits a row the head anchor covers, or
// one listed with its hash. So the store's two delete methods are reached only through the archive
// code (internal/core/audit, through its Store interface) and the adapter that joins it to the
// store, and a caller anywhere else fails here.
func TestOnlyTheArchiveDeletesFromTheChain(t *testing.T) {
	root := repoRoot(t)
	deletes := map[string]bool{"ArchiveAuditRows": true, "ArchiveRows": true, "DeleteAuditEventsThrough": true}
	allowed := map[string]bool{
		"internal/core/auditstore/auditstore.go": true, // the join
		"internal/core/audit/archive.go":         true, // the head archive and its repair
		"internal/core/audit/departed.go":        true, // an identity's archive
	}
	found := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/core/store/") {
			return nil // the methods' own bodies
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && deletes[sel.Sel.Name] {
					found[rel] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range found {
		if !allowed[rel] {
			t.Errorf("%s deletes from the audit chain; only the archive code may, which writes the rows out first", rel)
		}
	}
	for rel := range allowed {
		if !found[rel] {
			t.Errorf("%s no longer calls a delete on the chain: the list is stale", rel)
		}
	}
}

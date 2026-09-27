package settings

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An identity leaving this host erases its settings by the keys AccountKeys names
// (identity.Manager.Leave). A per-account key function that AccountKeys does not call would leave
// that account's value behind, naming an account that no longer exists. This finds every function
// in the package shaped like one — a single `accountID string` parameter, a string result — and
// checks the key it makes is among AccountKeys'.
func TestAccountKeysNamesEveryPerAccountKey(t *testing.T) {
	byName := map[string]func(string) string{
		"StorageKeyQuota":          StorageKeyQuota,
		"StorageKeyRetention":      StorageKeyRetention,
		"ContactsKeyRequestExpiry": ContactsKeyRequestExpiry,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var found []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				continue
			}
			ps := fn.Type.Params.List
			if len(ps) != 1 || len(ps[0].Names) != 1 || ps[0].Names[0].Name != "accountID" {
				continue
			}
			if id, ok := fn.Type.Results.List[0].Type.(*ast.Ident); !ok || id.Name != "string" {
				continue
			}
			found = append(found, fn.Name.Name)
		}
	}
	if len(found) < 3 {
		t.Fatalf("found %d per-account key functions, want at least the three this test was written against: the scan is looking at the wrong thing", len(found))
	}
	keys := map[string]bool{}
	for _, k := range AccountKeys("acct-1") {
		keys[k] = true
	}
	for _, name := range found {
		fn, ok := byName[name]
		if !ok {
			t.Errorf("%s makes a per-account key: add it to AccountKeys, and to this test's table", name)
			continue
		}
		if k := fn("acct-1"); !keys[k] {
			t.Errorf("AccountKeys does not name %s's key %q: leaving would keep it", name, k)
		}
	}
}

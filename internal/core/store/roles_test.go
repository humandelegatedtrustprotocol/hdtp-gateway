package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Store is the sum of its role interfaces and nothing else, so that a consumer can take the one
// role it needs. A method declared on Store itself would belong to no role, and no narrowed
// consumer could ever reach it: every method goes into the role for its area of the schema.
func TestStoreIsOnlyItsRoles(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "store.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	roles := 0
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Store" {
			return true
		}
		found = true
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatal("Store is not an interface")
		}
		for _, m := range it.Methods.List {
			if len(m.Names) > 0 {
				t.Errorf("Store declares %s itself; put it in the role interface for its area", m.Names[0].Name)
				continue
			}
			roles++
		}
		return false
	})
	if !found {
		t.Fatal("no Store interface in store.go; the guard is not looking at it")
	}
	if roles < 2 {
		t.Fatalf("Store embeds %d role interfaces; the guard is not reading what it should", roles)
	}
}

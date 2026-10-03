package integrationtest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The cloud holds itself to this node's owner MCP: every tool here is exactly one action there
// (`batondeck/gateway/test/mcp-owner.test.ts`, "parity with the Go node"). What it compares
// against is a JSON list of this node's tool names, and that list was a copy somebody typed. It
// had no `identity_certificate`, which this node has served since 2.0, and it would have kept a
// tool this node removed for as long as nobody looked — the parity test was green throughout,
// because it was true of the file it read.
//
// So the copy is checked where the truth is. The names are read from the syntax tree — every
// `mcp.Tool{Name: "…"}` literal in the package — and not with a pattern over the source text: two
// of them are registered with `Name:` on its own line, which is how a pattern missed them once.
func TestTheCloudsCopyOfTheOwnerToolsIsCurrent(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "..", "batondeck", "gateway", "test", "fixtures", "go-owner-tools.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("SKIPPED, and so the cloud's copy is unchecked: no batondeck beside this repo (%v)", err)
	}
	var doc struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}

	registered := map[string]bool{}
	dir := filepath.Join(root, "internal", "internalui", "ownermcp")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Tool" {
					return true
				}
				if pkgName, ok := sel.X.(*ast.Ident); !ok || pkgName.Name != "mcp" {
					return true
				}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
						continue
					}
					val, ok := kv.Value.(*ast.BasicLit)
					if !ok {
						t.Errorf("%s: an owner tool is named by something other than a string literal, which this test cannot read", fset.Position(kv.Pos()))
						continue
					}
					name, _ := strconv.Unquote(val.Value)
					registered[name] = true
				}
				return true
			})
		}
	}
	want := make([]string, 0, len(registered))
	for name := range registered {
		want = append(want, name)
	}
	sort.Strings(want)
	if len(want) < 20 {
		t.Fatalf("read only %d owner tools from %s: the reader is broken, not the fixture", len(want), dir)
	}
	got := append([]string(nil), doc.Tools...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("batondeck/gateway/test/fixtures/go-owner-tools.json is not this node's owner tools.\n  the fixture: %v\n  this node:   %v\n"+
			"Change the fixture to match, and then the cloud's parity test will say what the cloud owes.", got, want)
	}
}

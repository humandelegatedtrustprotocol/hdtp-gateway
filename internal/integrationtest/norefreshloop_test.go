package integrationtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The owner's rule, 2026-09-19: a pin is confirmed when it is needed, and the node does nothing
// proactively. HDTP §14.3 says the same of the protocol — a newer leaf arrives on use and needs
// no poll. The node polled anyway: `serve` re-fetched every contact's card two minutes after start
// and every six hours after, in original code that a first attempt at this rule walked straight
// past, because what it removed was a NAME it had itself given the interval. The second attempt
// removed the ticker and kept the sweep, for an owner-MCP tool that ran it on request. The rule as
// it stands now: no contact sync of any kind, except a refresh of ONE contact that a person asked
// for — a button on that contact's page, and the owner MCP's `refresh_contact`.
//
// So this is a guard on the shape, read from the syntax tree and not from names in prose:
//
//   - `node.RefreshContact` is reached from the two surfaces a person asks through and the wiring
//     that hands it to them, and from nowhere else;
//   - no call of it stands inside a loop or a goroutine, and no function that calls it starts a
//     timer — one call, for the one contact in the request, while the request is being answered;
//   - the `get_card` tool — the thing a sync DOES — is called from the places listed and no other,
//     so a new fetcher of cards has to be written down here with its reason.
func TestNothingRefreshesContactsByItself(t *testing.T) {
	root := repoRoot(t)
	callers := map[string]string{
		"internal/node/refresh.go":               "the definition",
		"internal/internalui/ownermcp/server.go": "the `refresh_contact` tool: one contact, on request",
		"internal/internalui/contacts_pages.go":  "POST /contacts/{fpr}/refresh: the button on one contact's page",
		"internal/cli/compose.go":                "the wiring that hands the method to those two surfaces",
	}
	fetchers := map[string]string{
		"internal/node/refresh.go":     "the refresh itself",
		"internal/outbound/seal.go":    "on use: a sealed call that met an unknown kid asks for the renewed leaf (§14.4)",
		"internal/node/contactcall.go": "the owner agent's call_contact allow-list and the tool list it shows",
		"internal/public/tools.go":     "SERVING get_card to a contact, which is the other end of the wire",
	}
	isRefresh := func(name string) bool { return name == "RefreshContact" || name == "refreshContact" }

	sawCaller, sawFetcher := map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			var stack []ast.Node
			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				switch v := n.(type) {
				case *ast.Ident:
					if isRefresh(v.Name) {
						sawCaller[rel] = true
					}
				case *ast.BasicLit:
					if v.Kind == token.STRING {
						if s, uerr := strconv.Unquote(v.Value); uerr == nil && s == "get_card" {
							sawFetcher[rel] = true
						}
					}
				case *ast.CallExpr:
					name := ""
					switch f := v.Fun.(type) {
					case *ast.SelectorExpr:
						name = f.Sel.Name
					case *ast.Ident:
						name = f.Name
					}
					if name != "RefreshContact" {
						return true
					}
					at := fset.Position(v.Pos())
					// Everything between the file and the call: a loop or a `go` anywhere above it is
					// the sweep coming back.
					var encl ast.Node
					for _, up := range stack[:len(stack)-1] {
						switch up.(type) {
						case *ast.ForStmt, *ast.RangeStmt:
							t.Errorf("%s:%d calls RefreshContact inside a loop: a refresh is of ONE contact", rel, at.Line)
						case *ast.GoStmt:
							t.Errorf("%s:%d calls RefreshContact from a goroutine: a refresh happens while a person's request is answered", rel, at.Line)
						case *ast.FuncDecl, *ast.FuncLit:
							encl = up
						}
					}
					if encl != nil && startsTimer(encl) {
						t.Errorf("%s:%d calls RefreshContact in a function that starts a timer: that is the shape this test exists to stop", rel, at.Line)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	compare := func(what string, want map[string]string, got map[string]bool) {
		for rel := range got {
			if _, ok := want[rel]; !ok {
				t.Errorf("%s %s and is not on this test's list. The node does not sync contacts by itself; "+
					"if this is a person asking about one contact, add the file here with the reason.", rel, what)
			}
		}
		var stale []string
		for rel := range want {
			if !got[rel] {
				stale = append(stale, rel)
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("listed here but no longer true — %s no longer %s; the guard's own list is stale", strings.Join(stale, ", "), what)
		}
	}
	compare("names RefreshContact", callers, sawCaller)
	compare(`names the "get_card" tool`, fetchers, sawFetcher)
}

// startsTimer reports whether the function body creates a ticker or a delayed call.
func startsTimer(fn ast.Node) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "time" {
			switch sel.Sel.Name {
			case "NewTicker", "Tick", "AfterFunc", "NewTimer", "After":
				found = true
			}
		}
		return true
	})
	return found
}

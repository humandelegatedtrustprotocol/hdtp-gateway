package integrationtest

// The node's packages form layers, and an import may only point down. Nothing held that: the
// survey of 2026-09-26 found the node importing the portal package for one handler, and the node
// and the public surface importing the calendar provider for its types, and each had arrived
// without anyone deciding it. A layer that can be reached into from below stops being a layer.
//
// The table is data. Every package under internal/ and cmd/ must have a rank, and a package may
// import only packages of a strictly lower rank. `cli` is the one package above every other (it
// wires them) and `cmd/pact-gateway` is above it. Only non-test files are read: a test may reach
// up to build its fixture.
//
// A known inversion that has not been fixed yet is named in layerExceptions with why. The list
// only shrinks: an exception that no longer occurs fails the test, so fixing an inversion and
// forgetting its entry cannot leave a hole for the next one.

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// layerRank is every package of the node, by rank. Lower ranks know nothing of higher ones.
var layerRank = map[string]int{
	// leaves: no other package of the node. `migrations` and `web` are the embedded SQL and
	// portal bundle at the module root.
	"migrations":                   0,
	"web":                          0,
	"internal/core":                0,
	"internal/core/audit":          0,
	"internal/core/policy":         0,
	"internal/core/store/sqlitedb": 0,
	"internal/core/store/pgdb":     0,
	"internal/envelope":            0,
	"internal/ingress/dns":         0,
	"internal/testid":              0,
	"internal/integrationtest":     0,
	// the store, over its generated engines
	"internal/core/store":             1,
	"internal/core/store/conformance": 2,
	// domain services
	"internal/identity":        2,
	"internal/messaging":       2,
	"internal/tunnel":          2,
	"internal/contacts":        3,
	"internal/outbound":        3,
	"internal/ingress":         3,
	"internal/integrations":    3,
	"internal/portable":        3,
	"internal/internalui/auth": 3,
	// the public surface
	"internal/public": 4,
	// the node, and the integration adapters it must not reach into
	"internal/node":                   5,
	"internal/integrations/providers": 5,
	"internal/integrations/recipes":   5,
	// the owner's surfaces: the portal and the owner MCP, which the node must not import
	"internal/internalui":          6,
	"internal/internalui/ownermcp": 6,
	// the wiring, and the binary
	"internal/cli":     7,
	"cmd/pact-gateway": 8,
}

// layerExceptions are inversions that exist today and are to be removed, each with why it is
// still here. Key: "importer -> imported".
var layerExceptions = map[string]string{
	"internal/node -> internal/internalui":               "node serves internalui.LandingHandler; refactor S2 injects it from cli",
	"internal/node -> internal/integrations/providers":   "node's calendarAt names providers.Slot and BookingAck; refactor S2 moves them behind a port",
	"internal/public -> internal/integrations/providers": "the public tools name providers.Slot, BookingAck and MaxSlots; refactor S2 moves them behind a port",
}

// nodeImports reads every non-test Go file under internal/ and cmd/ and returns, per package
// directory (relative to the module root), the node packages it imports.
func nodeImports(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			rel = filepath.ToSlash(rel)
			if out[rel] == nil {
				out[rel] = map[string]bool{}
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				// The identity core is its own module under this path; it is not a layer here.
				if !strings.HasPrefix(p, modulePath+"/") || strings.HasPrefix(p, modulePath+"/pact-identity") {
					continue
				}
				out[rel][strings.TrimPrefix(p, modulePath+"/")] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestImportsPointDownTheLayers(t *testing.T) {
	root := repoRoot(t)
	graph := nodeImports(t, root)

	// The control: a guard that reads nothing passes everything.
	if len(graph) < 25 {
		t.Fatalf("read %d packages; the node has more than that, so the walk is broken", len(graph))
	}
	if n := len(graph["internal/cli"]); n < 15 {
		t.Fatalf("internal/cli imports %d node packages as read; it wires nearly all of them, so the reader is broken", n)
	}

	var problems []string
	for pkg := range graph {
		if _, ok := layerRank[pkg]; !ok {
			problems = append(problems, pkg+" has no rank: add it to layerRank at the layer it belongs to")
		}
	}
	for pkg := range layerRank {
		if _, err := os.Stat(filepath.Join(root, pkg)); err != nil {
			problems = append(problems, pkg+" is ranked but does not exist: remove it from layerRank")
		}
	}
	seen := map[string]bool{}
	for pkg, imports := range graph {
		from, ok := layerRank[pkg]
		if !ok {
			continue
		}
		for imp := range imports {
			to, ok := layerRank[imp]
			if !ok {
				problems = append(problems, pkg+" imports "+imp+", which has no rank")
				continue
			}
			if to < from {
				continue
			}
			edge := pkg + " -> " + imp
			if _, excused := layerExceptions[edge]; excused {
				seen[edge] = true
				continue
			}
			problems = append(problems, edge+": rank "+strconv.Itoa(from)+" imports rank "+strconv.Itoa(to)+"; an import may only point down")
		}
	}
	for edge := range layerExceptions {
		if !seen[edge] {
			problems = append(problems, edge+" is excused but no longer happens: remove it from layerExceptions")
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

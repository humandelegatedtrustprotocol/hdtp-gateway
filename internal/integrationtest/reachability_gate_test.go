package integrationtest

// P10-01: gate the conformance map on product REACHABILITY, not test existence.
//
// TestConformanceDocCitesRealTests proves that every test the map names exists.
// That is a weaker claim than the map makes, and the gap is not theoretical: it
// is how five tasks came to read `done` on the board while the mechanism they
// covered was never wired into the shipped binary. A test can pass forever
// against a library `main` never calls.
//
// Two cheap, hermetic checks close the two shapes that actually occurred:
//
//   - a whole PACKAGE the binary never imports (P1–P5: nothing outside the
//     integration tests ever assembled a node; the recipe corpus is not in the
//     dependency graph at all);
//   - a CONSTRUCTOR whose only callers are tests (P10-02's rate limiter and
//     P10-03's session binder both shipped this way — built, tested, named in
//     PLAN.md's build goal as load-bearing, and never installed);
//   - an exported METHOD with no production caller, which is how most of this
//     project's unwired machinery actually looks: `ACME.Manage` never manages a
//     name, `Exposures.Reconcile` never runs the §6.5 stale guard,
//     `Client.SealedCall` never makes a sealed outbound call;
//   - an exported FUNCTION (not a constructor) with no production caller. The
//     review of 2026-09-23 found several at once (N-15) — `CardKey`, `PresetHolds`,
//     `SealToken`, `catalog.Diff` among them, the last one half of a portal feature
//     SPEC described and nothing rendered.
//
// `make analyze` runs golang.org/x/tools/cmd/deadcode against the same table
// (TestDeadcodeFindsOnlyWhatTheTableExcuses): whole-program, unexported names
// included, with no bare-name counter to share. This gate stays because it runs
// in `make check` with nothing to download, and because it owns the table's
// staleness.
//
// None of the three is a reachability proof: a function called only from another
// unreachable function still reads as reached, a hook left nil in a composite
// literal is invisible to all of them, and the method check counts by bare name,
// so two types sharing a method name share a counter. They are a floor, and the
// floor is placed exactly where this project has already fallen through.
//
// Known gaps live in the "Reachability" table of docs/conformance.md rather
// than in this file, so that the debt is visible to a reader of the map and not
// only to a reader of the tests. The table is self-cleaning: an entry that has
// become reachable fails just as loudly as a new violation, so it cannot
// quietly outlive the problem it documents.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/humandelegatedtrustprotocol/hdtp-gateway"

// binaryEntry is the shipped command. Reachability means "imported, directly or
// transitively, by this".
const binaryEntry = "cmd/hdtp-gateway"

func TestEveryMechanismIsReachableFromTheShippedBinary(t *testing.T) {
	root := repoRoot(t)
	allowed := reachabilityExceptions(t, root)
	used := map[string]bool{}

	imports, ctors, methods, funcs, prodRefs, testRefs := scanTree(t, root)

	/* ---- shape 1: packages the binary never imports ---- */

	reached := map[string]bool{}
	var walk func(string)
	walk = func(pkg string) {
		if reached[pkg] {
			return
		}
		reached[pkg] = true
		for _, dep := range imports[pkg] {
			walk(dep)
		}
	}
	walk(binaryEntry)

	var unreachable []string
	for pkg := range imports {
		if !strings.HasPrefix(pkg, "internal/") || reached[pkg] {
			continue
		}
		if allowed[pkg] {
			used[pkg] = true
			continue
		}
		unreachable = append(unreachable, pkg)
	}
	if len(unreachable) > 0 {
		sort.Strings(unreachable)
		t.Errorf("these packages are not reachable from %s, so nothing the conformance map\n"+
			"says about them is true of the shipped binary:\n  %s\n\n"+
			"Wire them, or add a row to the Reachability table in docs/conformance.md\n"+
			"saying why not and which board task fixes it.",
			binaryEntry, strings.Join(unreachable, "\n  "))
	}

	/* ---- shape 2: constructors only tests ever call ---- */

	var libraryOnly []string
	for name, pkg := range ctors {
		// The declaration itself is one production occurrence of the name; a
		// second means something in production names it.
		if prodRefs[name] > 0 {
			continue
		}
		if allowed[name] {
			used[name] = true
			continue
		}
		if testRefs[name] > 0 {
			libraryOnly = append(libraryOnly, name+" ("+pkg+")")
		}
	}
	if len(libraryOnly) > 0 {
		sort.Strings(libraryOnly)
		t.Errorf("these constructors are called only by tests — built, proven, and never\n"+
			"installed, which is the exact shape of the rate limiter and the session\n"+
			"binder:\n  %s\n\nWire them at the composition root, or add a row to the\n"+
			"Reachability table in docs/conformance.md.", strings.Join(libraryOnly, "\n  "))
	}

	/* ---- shape 3: exported methods nothing in production calls ---- */

	var deadMethods []string
	for name, where := range methods {
		if prodRefs[name] > 0 {
			continue
		}
		if allowed[where.key] {
			used[where.key] = true
			continue
		}
		kind := "is called only by tests"
		if testRefs[name] == 0 {
			kind = "is never called at all"
		}
		deadMethods = append(deadMethods, fmt.Sprintf("%s (%s) %s", where.key, where.pkg, kind))
	}
	if len(deadMethods) > 0 {
		sort.Strings(deadMethods)
		t.Errorf("these exported methods have no production caller — the shape most of this\n"+
			"project's unwired machinery takes:\n  %s\n\nWire them, or add a row to the\n"+
			"Reachability table in docs/conformance.md.", strings.Join(deadMethods, "\n  "))
	}

	/* ---- shape 4: exported functions nothing in production calls ---- */

	var deadFuncs []string
	for name, where := range funcs {
		if prodRefs[name] > 0 {
			continue
		}
		if allowed[where.key] {
			used[where.key] = true
			continue
		}
		kind := "is called only by tests"
		if testRefs[name] == 0 {
			kind = "is never called at all"
		}
		deadFuncs = append(deadFuncs, fmt.Sprintf("%s (%s) %s", where.key, where.pkg, kind))
	}
	if len(deadFuncs) > 0 {
		sort.Strings(deadFuncs)
		t.Errorf("these exported functions have no production caller:\n  %s\n\nDelete them (a test\n"+
			"helper belongs in a _test.go file or internal/testid), or add a row to the\n"+
			"Reachability table in docs/conformance.md saying who calls them.", strings.Join(deadFuncs, "\n  "))
	}

	/* ---- the table must not outlive the problem ---- */

	var stale []string
	for name := range allowed {
		if !used[name] {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("docs/conformance.md excuses these from reachability, but they are reachable\n"+
			"now (or no longer exist). Delete the rows — an exception that outlives its\n"+
			"reason is how the map rots:\n  %s", strings.Join(stale, "\n  "))
	}
}

// reachabilityExceptions reads the documented gaps. Keeping them in the map
// rather than in this file is the point: a reader of the conformance claims
// sees the exceptions next to the claims they qualify.
func reachabilityExceptions(t *testing.T, root string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "docs", "conformance.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start := strings.Index(doc, "## Reachability")
	if start < 0 {
		t.Fatal("docs/conformance.md has no Reachability section — P10-01 requires the " +
			"exceptions to be visible in the map itself")
	}
	section := doc[start:]
	if end := strings.Index(section[1:], "\n## "); end >= 0 {
		section = section[:end+1]
	}
	row := regexp.MustCompile(`(?m)^\|\s*` + "`" + `([^` + "`" + `]+)` + "`" + `\s*\|`)
	out := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		out[strings.TrimSpace(m[1])] = true
	}
	if len(out) == 0 {
		t.Fatal("the Reachability table in docs/conformance.md parsed to nothing — check its shape")
	}
	return out
}

// scanTree parses every Go file once and returns: the import graph between this
// module's own packages, the package each exported New* constructor is declared
// in, and how often every exported name occurs in production and in test files.
//
// Build tags are deliberately ignored. That can only make the reachable set
// larger, which makes this check weaker rather than wrong — a gate that fails
// on a platform-specific file would be removed, and a removed gate protects
// nothing.
func scanTree(t *testing.T, root string) (imports map[string][]string, ctors map[string]string,
	methods, funcs map[string]methodSite, prod, test map[string]int) {
	t.Helper()
	fset := token.NewFileSet()
	imports = map[string][]string{}
	ctors = map[string]string{}
	methods = map[string]methodSite{}
	funcs = map[string]methodSite{}
	prod, test = map[string]int{}, map[string]int{}

	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			pkg := filepath.ToSlash(filepath.Dir(rel))
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
			if perr != nil {
				return nil // a file this parser cannot read is not evidence of anything
			}
			// A file is "test" if Go says so, OR if it lives in a package that
			// exists only to be called from tests. internal/core/store/conformance
			// is the shared store suite: ordinary .go source, so Go compiles it as
			// production, and its calls therefore counted as production references.
			//
			// That hid a real defect. AddMembership had no production caller at
			// all — the owner MCP's list_accounts returned null on every node —
			// and this gate passed it, because conformance.go calls it twice
			// (P14-05c, P14-05d). The Reachability table already excuses this
			// package from the IMPORT check; its call sites need excusing too, or
			// any Store method exercised only by the conformance suite reads as
			// used.
			isTest := strings.HasSuffix(path, "_test.go") || isTestOnlyPackage(path)
			if _, seen := imports[pkg]; !seen {
				imports[pkg] = nil
			}
			if !isTest {
				for _, im := range f.Imports {
					p := strings.Trim(im.Path.Value, `"`)
					if after, ok := strings.CutPrefix(p, modulePath+"/"); ok {
						imports[pkg] = append(imports[pkg], after)
					}
				}
			}
			// A second pass over the full file for declarations and references.
			full, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return nil
			}
			if !isTest {
				for _, dcl := range full.Decls {
					fn, ok := dcl.(*ast.FuncDecl)
					if !ok || !fn.Name.IsExported() {
						continue
					}
					switch {
					case fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "New"):
						ctors[fn.Name.Name] = pkg
					case fn.Recv == nil:
						// Keyed `pkg.Func` by the package's last element, which is how
						// a Reachability row names a function.
						funcs[fn.Name.Name] = methodSite{key: pkg[strings.LastIndex(pkg, "/")+1:] + "." + fn.Name.Name, pkg: pkg}
					case fn.Recv != nil:
						if r := receiverName(fn); r != "" {
							methods[fn.Name.Name] = methodSite{key: r + "." + fn.Name.Name, pkg: pkg}
						}
					}
				}
			}
			// Count USES, not declarations. Counting every exported Ident made
			// a declaration its own reference, and anything declared more than
			// once — every Store method is declared in the interface, in both
			// engine wrappers and in both generated Queries types — started
			// above any threshold this gate could set. The one shape the gate
			// most needed to catch was the one it structurally could not.
			var visit func(n ast.Node) bool
			visit = func(n ast.Node) bool {
				switch d := n.(type) {
				case *ast.FuncDecl:
					// Everything except the name being declared.
					if d.Recv != nil {
						ast.Inspect(d.Recv, visit)
					}
					ast.Inspect(d.Type, visit)
					if d.Body != nil {
						ast.Inspect(d.Body, visit)
					}
					return false
				case *ast.InterfaceType:
					// Method specs are declarations of the name, not calls.
					for _, f := range d.Methods.List {
						ast.Inspect(f.Type, visit)
					}
					return false
				case *ast.StructType:
					// Field names are declarations; their types are uses.
					for _, f := range d.Fields.List {
						ast.Inspect(f.Type, visit)
					}
					return false
				case *ast.Ident:
					if ast.IsExported(d.Name) {
						if isTest {
							test[d.Name]++
						} else {
							prod[d.Name]++
						}
					}
				}
				return true
			}
			ast.Inspect(full, visit)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(imports[binaryEntry]) == 0 {
		t.Fatalf("%s imports nothing from this module — the scan is broken, not the code", binaryEntry)
	}
	return imports, ctors, methods, funcs, prod, test
}

// testOnlyPackages are directories whose regular .go files exist solely to be
// called from tests. Keep this in step with the package rows of the Reachability
// table in docs/conformance.md.
var testOnlyPackages = []string{
	"internal/core/store/conformance",
	"internal/integrationtest",
	"internal/limits/limitstest",
	"internal/testid",
}

// isTestOnlyPackage reports whether a path sits in one of them.
func isTestOnlyPackage(path string) bool {
	slashed := filepath.ToSlash(path)
	for _, p := range testOnlyPackages {
		if strings.Contains(slashed, "/"+p+"/") || strings.HasPrefix(slashed, p+"/") {
			return true
		}
	}
	return false
}

// methodSite is where an exported method or function is declared. The key is
// `Type.Method` or `pkg.Func`, which is what a Reachability row names.
type methodSite struct{ key, pkg string }

// receiverName reports the bare type name a method hangs off, pointer or not.
func receiverName(fn *ast.FuncDecl) string {
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

// TestDeadcodeFindsOnlyWhatTheTableExcuses holds golang.org/x/tools/cmd/deadcode's report to the
// Reachability table (review N-15). deadcode is whole-program — it follows calls from
// cmd/hdtp-gateway rather than counting names, and sees unexported functions — so it finds what
// the floor above cannot: a helper whose only caller is a test, however it is spelled.
//
// `make deadcode` (part of `make analyze`) runs the tool and hands its report here in
// HDTP_DEADCODE_REPORT, one `<package path> <name>` per line. Without that variable there is
// nothing to hold and the test says so; `make check` does not download the tool.
//
// The control: internal/testid is test-support by construction and always unreachable, so a
// report that names nothing in it is not a report of this tree — a wrong root, a filter that
// matches nothing — and fails rather than passing empty.
func TestDeadcodeFindsOnlyWhatTheTableExcuses(t *testing.T) {
	report := os.Getenv("HDTP_DEADCODE_REPORT")
	if report == "" {
		t.Skip("run by `make deadcode`, which supplies deadcode's report in HDTP_DEADCODE_REPORT")
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	allowed := reachabilityExceptions(t, repoRoot(t))
	var packages []string
	for row := range allowed {
		if strings.HasPrefix(row, "internal/") || strings.HasPrefix(row, "cmd/") {
			packages = append(packages, row)
		}
	}
	control := false
	var unexcused []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pkgPath, name, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("a line of the report is not `<package> <name>`: %q", line)
		}
		rel, ok := strings.CutPrefix(pkgPath, modulePath+"/")
		if !ok {
			t.Fatalf("the report names a package outside this module: %q", line)
		}
		if rel == "internal/testid" {
			control = true
		}
		key := name // a method arrives as Type.Method, which is how a row names it
		if !strings.Contains(name, ".") {
			key = rel[strings.LastIndex(rel, "/")+1:] + "." + name
		}
		excused := allowed[key]
		for _, p := range packages {
			if rel == p || strings.HasPrefix(rel, p+"/") {
				excused = true
			}
		}
		if !excused {
			unexcused = append(unexcused, key+" ("+rel+")")
		}
	}
	if !control {
		t.Fatalf("the deadcode report names nothing in internal/testid, which is never reachable from " +
			"the binary: it is not a report of this tree (wrong root or filter?)")
	}
	if len(unexcused) > 0 {
		sort.Strings(unexcused)
		t.Errorf("deadcode finds these unreachable from %s:\n  %s\n\nDelete them — a test helper "+
			"belongs in a _test.go file or internal/testid — or add a row to the Reachability table "+
			"in docs/conformance.md saying who calls them.", binaryEntry, strings.Join(unexcused, "\n  "))
	}
}

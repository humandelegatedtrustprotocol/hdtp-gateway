package registry

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Entry is one registered scenario: its spec, and where it is written.
type Entry struct {
	Spec
	// Package is the directory of its test, relative to the harness module ("scenario").
	Package string
	// Test is the name of the Test function whose body holds the spec.
	Test string
	// File is the test file, relative to the harness module.
	File string
}

// Scan reads every registry.Spec literal out of the harness module's test files under root.
//
// It is strict, because what it returns is what the tiers run and the docs list: a spec it cannot
// read, one outside a Test function, two in one Test, a duplicate id, or a Test in a
// *live_test.go file with no spec at all is an error, not a scenario quietly left out.
func Scan(root string) ([]Entry, error) {
	var out []Entry
	var problems []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "registry" || name == "cmd") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		es, ps, err := scanFile(path, rel)
		if err != nil {
			return err
		}
		out = append(out, es...)
		problems = append(problems, ps...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	seen := map[string]string{}
	for _, e := range out {
		if prev, ok := seen[e.ID]; ok {
			problems = append(problems, fmt.Sprintf("%s: id %s is already %s", e.File, e.ID, prev))
		}
		seen[e.ID] = e.Package + "." + e.Test
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("registry:\n  %s", strings.Join(problems, "\n  "))
	}
	slices.SortFunc(out, func(a, b Entry) int { return compareIDs(a.ID, b.ID) })
	return out, nil
}

// compareIDs orders by family letter, then by number: F1, F2, S2, S10, T5.
func compareIDs(a, b string) int {
	if c := cmp.Compare(a[:1], b[:1]); c != 0 {
		return c
	}
	na, _ := strconv.Atoi(a[1:])
	nb, _ := strconv.Atoi(b[1:])
	return cmp.Compare(na, nb)
}

func isSpecLit(n ast.Node) (*ast.CompositeLit, bool) {
	cl, ok := n.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Spec" {
		return nil, false
	}
	x, ok := sel.X.(*ast.Ident)
	return cl, ok && x.Name == "registry"
}

func scanFile(path, rel string) ([]Entry, []string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, nil, err
	}
	var out []Entry
	var problems []string
	pkg := filepath.ToSlash(filepath.Dir(rel))
	live := strings.HasSuffix(rel, "live_test.go")
	inTest := map[*ast.CompositeLit]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
			continue
		}
		var lits []*ast.CompositeLit
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if cl, ok := isSpecLit(n); ok {
				lits = append(lits, cl)
				inTest[cl] = true
			}
			return true
		})
		switch {
		case len(lits) > 1:
			problems = append(problems, fmt.Sprintf("%s: %s holds %d specs; a scenario is one Test", rel, fn.Name.Name, len(lits)))
		case len(lits) == 0 && live:
			problems = append(problems, fmt.Sprintf("%s: %s is a live test with no registry.Spec, so no tier can run it and no doc lists it", rel, fn.Name.Name))
		case len(lits) == 1:
			s, err := specOf(lits[0])
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s: %v", rel, fn.Name.Name, err))
				continue
			}
			if err := s.Validate(); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s: %v", rel, fn.Name.Name, err))
				continue
			}
			out = append(out, Entry{Spec: s, Package: pkg, Test: fn.Name.Name, File: rel})
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if cl, ok := isSpecLit(n); ok && !inTest[cl] {
			problems = append(problems, fmt.Sprintf("%s:%d: a registry.Spec outside a Test function; it must sit in the Test it describes",
				rel, fset.Position(cl.Pos()).Line))
		}
		return true
	})
	return out, problems, nil
}

// The names a spec literal may use, read from the constants in spec.go. scan_test.go holds these
// tables equal to the constants, so a tier or need added there and not here fails a test.
var (
	tierNames = map[string]Tier{"Fabric": Fabric, "PR": PR, "Nightly": Nightly}
	needNames = map[string]Need{
		"Docker": Docker, "NodeImage": NodeImage, "CaldavImage": CaldavImage,
		"Chrome": Chrome, "Kernel": Kernel, "CF": CF, "HDTPCLI": HDTPCLI, "CloudBattery": CloudBattery, "LocalCloud": LocalCloud,
	}
)

func specOf(cl *ast.CompositeLit) (Spec, error) {
	var s Spec
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return s, fmt.Errorf("a registry.Spec is written with field names")
		}
		key := kv.Key.(*ast.Ident).Name
		var err error
		switch key {
		case "ID":
			s.ID, err = stringOf(kv.Value)
		case "Name":
			s.Name, err = stringOf(kv.Value)
		case "Tier":
			var name string
			if name, err = registryName(kv.Value); err == nil {
				t, ok := tierNames[name]
				if !ok {
					err = fmt.Errorf("registry.%s is not a tier", name)
				}
				s.Tier = t
			}
		case "Needs":
			list, ok := kv.Value.(*ast.CompositeLit)
			if !ok {
				return s, fmt.Errorf("Needs must be a []registry.Need literal")
			}
			for _, e := range list.Elts {
				name, nerr := registryName(e)
				if nerr != nil {
					return s, nerr
				}
				n, ok := needNames[name]
				if !ok {
					return s, fmt.Errorf("registry.%s is not a need", name)
				}
				s.Needs = append(s.Needs, n)
			}
		case "Timeout":
			s.Timeout, err = durationOf(kv.Value)
		default:
			err = fmt.Errorf("unknown field %s", key)
		}
		if err != nil {
			return s, fmt.Errorf("%s: %w", key, err)
		}
	}
	return s, nil
}

func stringOf(e ast.Expr) (string, error) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", fmt.Errorf("must be a string literal")
	}
	return strconv.Unquote(b.Value)
}

func registryName(e ast.Expr) (string, error) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", fmt.Errorf("must be registry.<Name>")
	}
	if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "registry" {
		return "", fmt.Errorf("must be registry.<Name>")
	}
	return sel.Sel.Name, nil
}

var units = map[string]time.Duration{"Second": time.Second, "Minute": time.Minute, "Hour": time.Hour}

// durationOf reads `N * time.Minute` (or Second, or Hour), or a bare `time.Minute`.
func durationOf(e ast.Expr) (time.Duration, error) {
	unit := func(e ast.Expr) (time.Duration, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return 0, false
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "time" {
			return 0, false
		}
		u, ok := units[sel.Sel.Name]
		return u, ok
	}
	if u, ok := unit(e); ok {
		return u, nil
	}
	if bin, ok := e.(*ast.BinaryExpr); ok && bin.Op == token.MUL {
		if lit, ok := bin.X.(*ast.BasicLit); ok && lit.Kind == token.INT {
			if u, ok := unit(bin.Y); ok {
				n, err := strconv.Atoi(lit.Value)
				return time.Duration(n) * u, err
			}
		}
	}
	return 0, fmt.Errorf("must be N * time.Minute (or Second, or Hour)")
}

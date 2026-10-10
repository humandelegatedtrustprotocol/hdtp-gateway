package integrationtest

// SECURITY.md's "Current hardening status" is the public record of where the node stands, each row
// measured against the code on the day it was written. A row that nothing holds goes stale the day
// after. The rows that can be derived from the tree are held to it here: the fuzz targets and their
// time, the analysers and their pinned versions, the form of every gosec waiver, the versions of the
// libraries the table names, the scenario tiers, what the pre-push hook runs, the absence of
// Dependabot and CI, and that every test the table cites exists. A change to any of those changes
// the record in the same commit, or fails the build.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestTheHardeningStatusTableMatchesTheTree(t *testing.T) {
	root := repoRoot(t)
	security := readDoc(t, root, "SECURITY.md")
	rows := hardeningRows(t, security)
	makefile := readDoc(t, root, "Makefile")
	gomod := readDoc(t, root, "go.mod")

	t.Run("fuzz targets", func(t *testing.T) {
		row := rows.get(t, "Fuzzing")
		defined := map[string]bool{}
		err := filepath.WalkDir(filepath.Join(root, "internal"), walkGoTests(func(_ string, src []byte) {
			for _, m := range fuzzFunc.FindAllStringSubmatch(string(src), -1) {
				defined[m[1]] = true
			}
		}))
		if err != nil {
			t.Fatal(err)
		}
		if len(defined) == 0 {
			t.Fatal("no fuzz targets in the tree; this check is looking at nothing")
		}
		for name := range defined {
			if !strings.Contains(row, "`"+name+"`") {
				t.Errorf("the tree defines %s and the Fuzzing row does not name it", name)
			}
		}
		for _, m := range regexp.MustCompile("`(Fuzz\\w+)`").FindAllStringSubmatch(row, -1) {
			if !defined[m[1]] {
				t.Errorf("the Fuzzing row names %s, which the tree does not define", m[1])
			}
		}
		times := map[string]bool{}
		for _, m := range regexp.MustCompile(`-fuzztime (\d+)s`).FindAllStringSubmatch(fuzzRecipe(t, makefile), -1) {
			times[m[1]] = true
		}
		if len(times) != 1 {
			t.Fatalf("make fuzz runs its targets for %v seconds; the row says one time for all", keys(times))
		}
		if want := keys(times)[0] + " s each"; !strings.Contains(row, want) {
			t.Errorf("make fuzz runs each target for %s; the Fuzzing row does not say %q", keys(times)[0]+"s", want)
		}
	})

	t.Run("analysers", func(t *testing.T) {
		row := rows.get(t, "Static analysis")
		pinned := analysers(t, makefile)
		for tool, version := range pinned {
			if want := "`" + tool + "` " + version; !strings.Contains(row, want) {
				t.Errorf("make analyze runs %s %s; the Static analysis row does not say %q", tool, version, want)
			}
		}
		for _, m := range regexp.MustCompile("`([a-z]+)` (v?\\d[\\w.]*)").FindAllStringSubmatch(row, -1) {
			if v, ok := pinned[m[1]]; !ok {
				t.Errorf("the Static analysis row names %s %s, which make analyze does not run", m[1], m[2])
			} else if v != m[2] {
				t.Errorf("the Static analysis row says %s %s; make analyze runs %s", m[1], m[2], v)
			}
		}
	})

	t.Run("every gosec waiver names its rule and reason", func(t *testing.T) {
		// The annotation is spelt in two halves here so that this file, which speaks of it, is
		// held to the same rule as every other.
		nosec := "#no" + "sec"
		if !strings.Contains(rows.get(t, "Static analysis"), "every `"+nosec+"` in the tree names the rule it waives and the reason on the same line") {
			t.Fatal("the Static analysis row no longer makes the claim this check holds; change both")
		}
		form := regexp.MustCompile(nosec + ` G\d{3} -- \S`)
		found := 0
		for _, dir := range []string{"cmd", "internal"} {
			err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
					return err
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				for i, line := range strings.Split(string(b), "\n") {
					if !strings.Contains(line, nosec) {
						continue
					}
					found++
					if !form.MatchString(line) {
						rel, _ := filepath.Rel(root, p)
						t.Errorf("%s:%d waives a gosec finding without naming the rule and the reason (`%s Gnnn -- why`)", rel, i+1, nosec)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		if found == 0 {
			t.Fatal("no gosec waiver in the tree; this check is looking at nothing")
		}
	})

	t.Run("no dependabot, no CI", func(t *testing.T) {
		row := rows.get(t, "Dependencies")
		for _, p := range []string{".github/dependabot.yml", ".github/workflows"} {
			if _, err := os.Stat(filepath.Join(root, p)); err == nil {
				t.Errorf("%s exists; the Dependencies row says it does not", p)
			}
			if want := "`" + p + "` does not exist"; !strings.Contains(row, want) {
				t.Errorf("the Dependencies row no longer says %q", want)
			}
		}
	})

	t.Run("library versions", func(t *testing.T) {
		versions := requiredVersions(gomod)
		for _, c := range []struct{ row, module, format string }{
			{"Dependencies", "github.com/humandelegatedtrustprotocol/hdtp-identity/go", "`go.mod`: %s"},
			{"Interoperability", "github.com/humandelegatedtrustprotocol/hdtp-identity/go", "hdtp-identity %s"},
			{"Dependencies", "github.com/fatedier/frp", "frp %s"},
			{"Owner surface authentication", "github.com/go-webauthn/webauthn", "`go-webauthn` %s"},
			{"Authorization", "github.com/cedar-policy/cedar-go", "`cedar-go` %s"},
		} {
			v, ok := versions[c.module]
			if !ok {
				t.Fatalf("go.mod does not require %s", c.module)
			}
			if c.format == "hdtp-identity %s" {
				v = strings.TrimPrefix(v, "v")
			}
			if want := fmt.Sprintf(c.format, v); !strings.Contains(rows.get(t, c.row), want) {
				t.Errorf("go.mod requires %s %s; the %s row does not say %q", c.module, versions[c.module], c.row, want)
			}
		}
	})

	t.Run("scenario tiers", func(t *testing.T) {
		row := rows.get(t, "Automated tests")
		tiers := scenarioTiers(t, filepath.Join(root, "harness"))
		total := tiers["fabric"] + tiers["pr"] + tiers["nightly"]
		if total == 0 {
			t.Fatal("no registry.Spec in the harness; this check is looking at nothing")
		}
		for _, want := range []string{
			fmt.Sprintf("%d live scenarios", total),
			fmt.Sprintf("%d fabric, %d PR, %d nightly", tiers["fabric"], tiers["pr"], tiers["nightly"]),
		} {
			if !strings.Contains(row, want) {
				t.Errorf("the harness registers %v; the Automated tests row does not say %q", tiers, want)
			}
		}
	})

	t.Run("what the hook runs", func(t *testing.T) {
		row := rows.get(t, "Automated tests")
		hook := readDoc(t, root, "githooks/pre-push")
		steps := regexp.MustCompile(`(?m)^step (\S+)`).FindAllStringSubmatch(hook, -1)
		if len(steps) == 0 {
			t.Fatal("githooks/pre-push runs no unconditional step; this check is looking at nothing")
		}
		for _, m := range steps {
			if want := "`make " + m[1] + "`"; !strings.Contains(row, want) {
				t.Errorf("the pre-push hook runs %s; the Automated tests row does not say %q", want, want)
			}
		}
	})

	t.Run("cited tests exist", func(t *testing.T) {
		have := map[string]bool{}
		for _, dir := range []string{"cmd", "internal", "harness"} {
			err := filepath.WalkDir(filepath.Join(root, dir), walkGoTests(func(_ string, src []byte) {
				for _, m := range regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w+)\(`).FindAllStringSubmatch(string(src), -1) {
					have[m[1]] = true
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
		}
		var missing []string
		for _, m := range citedTest.FindAllStringSubmatch(security, -1) {
			if !have[m[1]] {
				missing = append(missing, m[1])
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("SECURITY.md cites tests that do not exist: %s", strings.Join(missing, ", "))
		}
	})
}

// hardeningTable is the "Current hardening status" table, row by area.
type hardeningTable map[string]string

func (h hardeningTable) get(t *testing.T, area string) string {
	t.Helper()
	row, ok := h[area]
	if !ok {
		t.Fatalf("SECURITY.md's hardening-status table has no %q row; its areas are %v", area, keys(toSet(h)))
	}
	return row
}

func toSet(h hardeningTable) map[string]bool {
	s := make(map[string]bool, len(h))
	for k := range h {
		s[k] = true
	}
	return s
}

// hardeningRows reads the table under "## Current hardening status": one row per area, the area
// its first cell.
func hardeningRows(t *testing.T, security string) hardeningTable {
	t.Helper()
	_, section, ok := strings.Cut(security, "\n## Current hardening status\n")
	if !ok {
		t.Fatal("SECURITY.md has no \"## Current hardening status\" section")
	}
	if i := strings.Index(section, "\n## "); i >= 0 {
		section = section[:i]
	}
	rows := hardeningTable{}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Area |") {
			continue
		}
		area, rest, ok := strings.Cut(strings.TrimPrefix(line, "| "), " | ")
		if !ok {
			continue
		}
		rows[area] = strings.TrimSuffix(rest, " |")
	}
	if len(rows) == 0 {
		t.Fatal("the hardening-status table has no rows")
	}
	return rows
}

// analysers is every tool `make analyze` runs, by its name, with the version it is pinned to: the
// prerequisites of the analyze target, each recipe's `go run <module>@<version>` with the
// Makefile's own variables expanded one level.
func analysers(t *testing.T, makefile string) map[string]string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^analyze: (.*)$`).FindStringSubmatch(makefile)
	if m == nil {
		t.Fatal("the Makefile has no analyze target with prerequisites")
	}
	variable := regexp.MustCompile(`\$\(([A-Z_]+)\)`)
	goRun := regexp.MustCompile(`go run (\S+)@(\S+)`)
	out := map[string]string{}
	for _, target := range strings.Fields(m[1]) {
		recipe := variable.ReplaceAllStringFunc(makeRecipe(t, makefile, target), func(ref string) string {
			name := variable.FindStringSubmatch(ref)[1]
			if def := regexp.MustCompile(`(?m)^` + name + ` := (.*)$`).FindStringSubmatch(makefile); def != nil {
				return def[1]
			}
			return ref
		})
		// A recipe may run its tool more than once (vulncheck does, over the module and then over
		// upstream frp); it is one tool at one version.
		tools := map[string]string{}
		for _, run := range goRun.FindAllStringSubmatch(recipe, -1) {
			tool := path.Base(run[1])
			if v, ok := tools[tool]; ok && v != run[2] {
				t.Fatalf("make %s runs %s at %s and at %s", target, tool, v, run[2])
			}
			tools[tool] = run[2]
		}
		if len(tools) != 1 {
			t.Fatalf("make %s runs %d tools with go run; the table names one per target", target, len(tools))
		}
		for tool, version := range tools {
			out[tool] = version
		}
	}
	return out
}

// makeRecipe is the recipe of one Makefile target: the tab-indented lines after `target:`.
func makeRecipe(t *testing.T, makefile, target string) string {
	t.Helper()
	var out strings.Builder
	in := false
	for _, line := range strings.Split(makefile, "\n") {
		switch {
		case strings.HasPrefix(line, target+":"):
			in = true
		case in && strings.HasPrefix(line, "\t"):
			out.WriteString(line)
			out.WriteByte('\n')
		case in:
			in = false
		}
	}
	if out.Len() == 0 {
		t.Fatalf("the Makefile has no %s: target with a recipe", target)
	}
	return out.String()
}

// requiredVersions is go.mod's require block, module to version.
func requiredVersions(gomod string) map[string]string {
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\S+\.\S+) (v\d\S*)`).FindAllStringSubmatch(gomod, -1) {
		if _, dup := out[m[1]]; !dup {
			out[m[1]] = m[2]
		}
	}
	return out
}

// scenarioTiers counts the harness's registered scenarios per tier: every registry.Spec literal in
// a test file, read as harness/registry's Scan reads them (the registry's own tests, cmd, testdata
// and dot-directories skipped), its ID and its Tier.
func scenarioTiers(t *testing.T, harness string) map[string]int {
	t.Helper()
	seen := map[string]string{}
	counts := map[string]int{}
	err := filepath.WalkDir(harness, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != harness && (strings.HasPrefix(name, ".") || name == "testdata" || name == "registry" || name == "cmd") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Spec" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "registry" {
				return true
			}
			var id, tier string
			for _, e := range lit.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch kv.Key.(*ast.Ident).Name {
				case "ID":
					if s, ok := kv.Value.(*ast.BasicLit); ok {
						id, _ = strconv.Unquote(s.Value)
					}
				case "Tier":
					if s, ok := kv.Value.(*ast.SelectorExpr); ok {
						tier = strings.ToLower(s.Sel.Name)
					}
				}
			}
			rel, _ := filepath.Rel(harness, p)
			if id == "" || tier == "" {
				t.Errorf("%s: a registry.Spec without a literal ID and Tier", rel)
				return true
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("%s: scenario %s is already registered in %s", rel, id, prev)
			}
			seen[id] = rel
			counts[tier]++
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return counts
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

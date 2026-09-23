package integrationtest

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// docs/conformance.md claims a passing test for every PACT §12 clause, error
// code and limit. This is what stops that claim from rotting: every test name
// the document cites must exist somewhere in the tree. A renamed or deleted
// test fails the build here, where the mismatch is cheap to fix, rather than
// being discovered by a reader trusting the map.
func TestConformanceDocCitesRealTests(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "docs", "conformance.md"))
	if err != nil {
		t.Fatalf("docs/conformance.md is part of the definition of done: %v", err)
	}
	cited := regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`").FindAllStringSubmatch(string(doc), -1)
	if len(cited) < 40 {
		t.Fatalf("conformance doc cites only %d tests — that is not a map of §12", len(cited))
	}
	defined := definedTests(t, root)
	var missing []string
	seen := map[string]bool{}
	for _, m := range cited {
		name := m[1]
		if seen[name] || defined[name] {
			continue
		}
		seen[name] = true
		missing = append(missing, name)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("docs/conformance.md cites tests that do not exist: %s", strings.Join(missing, ", "))
	}
}

// definedTests collects every Test/Fuzz function name in the node's tree.
func definedTests(t *testing.T, root string) map[string]bool {
	t.Helper()
	return definedTestsUnder(t, filepath.Join(root, "internal"))
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the module root")
	return ""
}

// The map's "Where it lives" column rotted where the test-name check could not see it: a row cited
// `internal/node/node.go` (`DeliverSealed` — the relay path) for a function deleted with the relay
// (review N-13). This resolves every backticked token of that column in every table that has one:
// a path must exist (`{a,b}` and `*` expanded); a bare file name must exist beside a path the same
// cell names; and an identifier must be declared — a func, method, type, var or const — in the Go
// files the same cell names.
func TestConformanceDocLocationsExist(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "docs", "conformance.md"))
	if err != nil {
		t.Fatal(err)
	}
	tick := regexp.MustCompile("`([^`]+)`")
	col := -1
	cells := 0
	for _, line := range strings.Split(string(doc), "\n") {
		if !strings.HasPrefix(line, "|") {
			col = -1
			continue
		}
		row := strings.Split(strings.Trim(line, "|"), "|")
		if col < 0 {
			for i, h := range row {
				if strings.TrimSpace(h) == "Where it lives" {
					col = i
				}
			}
			continue
		}
		if col >= len(row) || strings.HasPrefix(strings.TrimSpace(row[0]), "---") {
			continue
		}
		cells++
		var paths, bare, idents []string
		for _, m := range tick.FindAllStringSubmatch(row[col], -1) {
			switch tok := m[1]; {
			case strings.Contains(tok, "/"):
				paths = append(paths, tok)
			case strings.HasSuffix(tok, ".go"):
				bare = append(bare, tok)
			default:
				idents = append(idents, tok)
			}
		}
		var files, dirs []string
		for _, p := range paths {
			matched := expandCited(t, root, p)
			if len(matched) == 0 {
				t.Errorf("docs/conformance.md cites %s, which does not exist: %s", p, strings.TrimSpace(row[0]))
			}
			for _, f := range matched {
				if st, err := os.Stat(f); err == nil && st.IsDir() {
					dirs = append(dirs, f)
					gos, _ := filepath.Glob(filepath.Join(f, "*.go"))
					files = append(files, gos...)
				} else {
					dirs = append(dirs, filepath.Dir(f))
					files = append(files, f)
				}
			}
		}
		for _, b := range bare {
			found := false
			for _, d := range dirs {
				if _, err := os.Stat(filepath.Join(d, b)); err == nil {
					found = true
					files = append(files, filepath.Join(d, b))
				}
			}
			if !found {
				t.Errorf("docs/conformance.md cites %s beside %v, and no such file is there", b, paths)
			}
		}
		for _, id := range idents {
			decl := regexp.MustCompile(`(?m)^(func (\([^)]*\) )?` + regexp.QuoteMeta(id) + `\b|type ` + regexp.QuoteMeta(id) + `\b|\t` + regexp.QuoteMeta(id) + `\s+(=|[A-Za-z*\[])|(var|const) ` + regexp.QuoteMeta(id) + `\b)`)
			found := false
			for _, f := range files {
				if b, err := os.ReadFile(f); err == nil && decl.Match(b) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("docs/conformance.md cites %s in %v, and nothing there declares it", id, paths)
			}
		}
	}
	if cells < 20 {
		t.Fatalf("read only %d \"Where it lives\" cells: the reader is broken, not the map", cells)
	}
}

// expandCited resolves a cited path, relative to the module root, with `{a,b}` alternatives and
// `*` globs.
func expandCited(t *testing.T, root, p string) []string {
	t.Helper()
	alts := []string{p}
	if a, b := strings.Index(p, "{"), strings.Index(p, "}"); a >= 0 && b > a {
		alts = nil
		for _, alt := range strings.Split(p[a+1:b], ",") {
			alts = append(alts, p[:a]+alt+p[b+1:])
		}
	}
	var out []string
	for _, alt := range alts {
		m, err := filepath.Glob(filepath.Join(root, alt))
		if err != nil {
			t.Fatal(err)
		}
		if len(m) == 0 {
			return nil
		}
		out = append(out, m...)
	}
	return out
}

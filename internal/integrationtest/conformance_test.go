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

// definedTests collects every Test/Fuzz function name in the tree.
func definedTests(t *testing.T, root string) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
	out := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
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

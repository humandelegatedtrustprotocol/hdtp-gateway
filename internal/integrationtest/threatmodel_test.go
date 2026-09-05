package integrationtest

// docs/threat-model.md is the reviewer-facing document, and its whole value is
// that every claim names the test that holds it. A citation that no longer
// resolves is worse than no citation: it reads as evidence while proving nothing,
// and renaming a test is exactly the kind of change nobody thinks to check a doc
// against.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var citedTest = regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`")

// Every security document that offers a test as evidence, not just the first one.
var docsCitingTests = []string{"threat-model.md", "crypto-review-brief.md"}

func TestThreatModelCitesRealTests(t *testing.T) {
	root := repoRoot(t)

	var doc []byte
	for _, name := range docsCitingTests {
		b, err := os.ReadFile(filepath.Join(root, "docs", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		doc = append(doc, b...)
	}

	have := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), walkGoTests(func(_ string, src []byte) {
		for _, m := range regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w+)\(`).FindAllStringSubmatch(string(src), -1) {
			have[m[1]] = true
		}
	}))
	if err != nil {
		t.Fatal(err)
	}

	cited := map[string]bool{}
	for _, m := range citedTest.FindAllStringSubmatch(string(doc), -1) {
		cited[m[1]] = true
	}
	if len(cited) == 0 {
		t.Fatal("these documents cite no tests at all; either they or this check is wrong")
	}

	var missing []string
	for name := range cited {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%v cite tests that do not exist: %s\n"+
			"A security document whose evidence does not resolve is worse than one "+
			"with no evidence. Fix the citation or restore the test.",
			docsCitingTests, strings.Join(missing, ", "))
	}
}

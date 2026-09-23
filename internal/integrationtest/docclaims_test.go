package integrationtest

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The README's "why you might trust this" section and SPEC §14.1 state numbers and name tests.
// Each claim below had gone stale by the review of 2026-09-23 (N-09, N-10, N-11): a table of
// "nine live scenarios" naming a relay that no longer exists, a test count a hundred short, a fuzz
// list naming a wire format nothing fuzzed, and an in-process scenario of the relay. These hold
// each such claim to what the tree has, so the next one fails here instead of in a review.

// liveScenarioTests are the Test functions of harness/scenario/*_live_test.go: the live
// scenarios, as the README's table means them.
func liveScenarioTests(t *testing.T, root string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "harness", "scenario", "*_live_test.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no live scenarios under harness/scenario: %v", err)
	}
	out := map[string]bool{}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
	}
	return out
}

func readDoc(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The README's scenario table is the live scenarios on disk, one row each, and the number in the
// sentence above it is how many there are.
func TestReadmeScenarioTableIsTheLiveScenarios(t *testing.T) {
	root := repoRoot(t)
	readme := readDoc(t, root, "README.md")
	m := regexp.MustCompile(`\*\*A harness that builds the world\.\*\* (\d+) live scenarios`).FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("README no longer states how many live scenarios there are where this test reads it")
	}
	start := strings.Index(readme, "| Scenario | What is real about it | Test |")
	if start < 0 {
		t.Fatal("README's scenario table has no Test column where this test reads it")
	}
	var rows []string
	for _, line := range strings.Split(readme[start:], "\n")[2:] {
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		name := regexp.MustCompile("`(Test[A-Za-z0-9_]+)`").FindStringSubmatch(cells[len(cells)-1])
		if name == nil {
			t.Errorf("README scenario row names no test: %s", line)
			continue
		}
		rows = append(rows, name[1])
	}
	live := liveScenarioTests(t, root)
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r] {
			t.Errorf("README's scenario table lists %s twice", r)
		}
		seen[r] = true
		if !live[r] {
			t.Errorf("README's scenario table lists %s, which is not a live scenario under harness/scenario", r)
		}
	}
	for name := range live {
		if !seen[name] {
			t.Errorf("%s is a live scenario and README's table does not list it", name)
		}
	}
	if n, _ := strconv.Atoi(m[1]); n != len(live) {
		t.Errorf("README says %d live scenarios; harness/scenario has %d", n, len(live))
	}
}

// Every test the README or the SPEC names by name exists, in the node or in the harness; and each
// of SPEC §14.1's in-process scenarios names at least one.
func TestReadmeAndSpecCiteRealTests(t *testing.T) {
	root := repoRoot(t)
	defined := definedTests(t, root)
	for name := range definedTestsUnder(t, filepath.Join(root, "harness")) {
		defined[name] = true
	}
	cite := regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`")
	for _, doc := range []string{"README.md", "SPEC.md"} {
		for _, m := range cite.FindAllStringSubmatch(readDoc(t, root, doc), -1) {
			if !defined[m[1]] {
				t.Errorf("%s names %s, which is not a test in this tree", doc, m[1])
			}
		}
	}
	spec := readDoc(t, root, "SPEC.md")
	a := strings.Index(spec, "**Integration scenarios.**")
	if a < 0 {
		t.Fatal("SPEC §14.1 has no integration scenarios where this test reads them")
	}
	items := 0
	for _, line := range strings.Split(spec[a:], "\n")[1:] {
		if strings.TrimSpace(line) == "" {
			if items > 0 {
				break
			}
			continue
		}
		if !regexp.MustCompile(`^\d+\. `).MatchString(line) {
			break
		}
		items++
		if !cite.MatchString(line) {
			t.Errorf("SPEC §14.1 scenario names no test: %s", line)
		}
	}
	if items < 3 {
		t.Fatalf("read only %d SPEC §14.1 scenarios: the reader is broken, not the SPEC", items)
	}
}

// The README states a floor on the node's test functions; the tree holds at least that many.
func TestReadmeTestCountIsAFloorTheTreeMeets(t *testing.T) {
	root := repoRoot(t)
	m := regexp.MustCompile(`More than (\d+) test functions`).FindStringSubmatch(readDoc(t, root, "README.md"))
	if m == nil {
		t.Fatal("README no longer states its test floor where this test reads it")
	}
	floor, _ := strconv.Atoi(m[1])
	n := 0
	for _, dir := range []string{"cmd", "internal"} {
		for name := range definedTestsUnder(t, filepath.Join(root, dir)) {
			if strings.HasPrefix(name, "Test") {
				n++
			}
		}
	}
	if n <= floor {
		t.Errorf("README says more than %d test functions; cmd and internal have %d", floor, n)
	}
}

// The README's fuzz list and SPEC §14.1's are the fuzz targets in the tree: all of them, and
// nothing else.
func TestDocsNameEveryFuzzTargetAndNoOther(t *testing.T) {
	root := repoRoot(t)
	var targets []string
	for name := range definedTestsUnder(t, filepath.Join(root, "internal")) {
		if strings.HasPrefix(name, "Fuzz") {
			targets = append(targets, name)
		}
	}
	sort.Strings(targets)
	want := strings.Join(targets, " ")
	for _, c := range []struct{ doc, from string }{
		{"README.md", "**Tests that run the product rather than a mock.**"},
		{"SPEC.md", "**Fuzzing.**"},
	} {
		text := readDoc(t, root, c.doc)
		a := strings.Index(text, c.from)
		if a < 0 {
			t.Fatalf("%s has no paragraph %q where this test reads it", c.doc, c.from)
		}
		para := text[a:]
		if b := strings.Index(para, "\n\n"); b > 0 {
			para = para[:b]
		}
		set := map[string]bool{}
		for _, m := range regexp.MustCompile("`(Fuzz[A-Za-z0-9_]+)`").FindAllStringSubmatch(para, -1) {
			set[m[1]] = true
		}
		var got []string
		for k := range set {
			got = append(got, k)
		}
		sort.Strings(got)
		if strings.Join(got, " ") != want {
			t.Errorf("%s's paragraph %q names fuzz targets %v; the tree has %v", c.doc, c.from, got, targets)
		}
	}
}

// definedTestsUnder collects every Test/Fuzz function declared in a _test.go file under dir.
func definedTestsUnder(t *testing.T, dir string) map[string]bool {
	t.Helper()
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
	out := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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

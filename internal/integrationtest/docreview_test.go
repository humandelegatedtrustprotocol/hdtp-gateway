package integrationtest

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The review of 2026-09-28's drift (D1, D2, D4): claims in the documents that no test held.

// D1. A relative link in a document this repository publishes resolves to a file in it. README and
// RELEASING linked ../SECURITY.md and ../LICENSE, files of the umbrella that holds this repository,
// which do not exist in a clone of it.
func TestRelativeLinksInTheDocsResolve(t *testing.T) {
	root := repoRoot(t)
	docs := []string{"README.md", "RELEASING.md", "SPEC.md", "CONTRIBUTING.md", "SUPPORT.md", "CHANGELOG.md"}
	more, _ := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	for _, m := range more {
		rel, _ := filepath.Rel(root, m)
		docs = append(docs, rel)
	}
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	checked := 0
	for _, d := range docs {
		b, err := os.ReadFile(filepath.Join(root, d))
		if err != nil {
			continue
		}
		for _, m := range link.FindAllStringSubmatch(string(b), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			target = strings.SplitN(target, "#", 2)[0]
			if target == "" {
				continue
			}
			checked++
			// In this repository, wherever it is checked out: a clone has no umbrella around it.
			abs := filepath.Clean(filepath.Join(root, filepath.Dir(d), target))
			if rel, err := filepath.Rel(root, abs); err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				t.Errorf("%s links %s, outside this repository", d, m[1])
				continue
			}
			if _, err := os.Stat(abs); err != nil {
				t.Errorf("%s links %s, which is not in this repository", d, m[1])
			}
		}
	}
	if checked < 10 {
		t.Fatalf("checked %d relative links: this test is looking at nothing", checked)
	}
}

// D2. SPEC.md's version line and docs/conformance.md name one PACT version: they are two copies of
// one fact (SPEC.md said 2.1.3 and the conformance map 2.1).
func TestSpecAndTheConformanceMapNameOnePACTVersion(t *testing.T) {
	root := repoRoot(t)
	spec := regexp.MustCompile(`implements PACT (\d+\.\d+\.\d+)`).FindStringSubmatch(readDoc(t, root, "SPEC.md"))
	conf := regexp.MustCompile(`(?m)^PACT (\d+\.\d+(?:\.\d+)?) \(`).FindStringSubmatch(readDoc(t, root, "docs/conformance.md"))
	if spec == nil || conf == nil || spec[1] != conf[1] {
		t.Fatalf("SPEC.md implements PACT %v; docs/conformance.md maps PACT %v", spec, conf)
	}
}

// D4. Every reason an install is refused with, on either door, is one SPEC §3.12 names.
func TestSpecNamesEveryReasonAnInstallIsRefused(t *testing.T) {
	root := repoRoot(t)
	reason := regexp.MustCompile(`"account_leaf_install_refused",[^\n]*reason:([a-z_]+)`)
	found := map[string]bool{}
	for _, dir := range []string{"internal/cli", "internal/internalui"} {
		files, _ := filepath.Glob(filepath.Join(root, dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(f)
			for _, m := range reason.FindAllStringSubmatch(string(b), -1) {
				found[m[1]] = true
			}
		}
	}
	if len(found) < 3 {
		t.Fatalf("found the reasons %v: this test is looking at nothing", found)
	}
	spec := readDoc(t, root, "SPEC.md")
	var missing []string
	for r := range found {
		if !strings.Contains(spec, "reason `"+r+"`") {
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("SPEC.md does not name the install refusal reason(s) %v", missing)
	}
}

// D3. docs/operations.md states the import-growth gate's bound, and it is the bound the test
// holds (internal/portable/scale_test.go growthBound); it said "grows faster than linearly", which
// the test did not hold (4x the threads may take up to the bound's times as long).
func TestOperationsStatesTheBoundTheScaleGateHolds(t *testing.T) {
	root := repoRoot(t)
	src := readDoc(t, root, "internal/portable/scale_test.go")
	m := regexp.MustCompile(`(?m)^const growthBound = (\d+)$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("scale_test.go declares no growthBound")
	}
	if want := "more than " + m[1] + " times as long for 4 times the threads"; !strings.Contains(readDoc(t, root, "docs/operations.md"), want) {
		t.Fatalf("docs/operations.md does not say %q", want)
	}
}

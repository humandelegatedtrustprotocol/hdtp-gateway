package integrationtest

// A GitHub Action referenced by tag is mutable: the tag can be repointed at any
// commit, so `@v4` is a promise from whoever controls that tag, not a fact about
// what will run. For a workflow that holds `contents: write` and `id-token: write`
// — that is, one that can sign artifacts in this project's name — that is the
// whole supply chain. Pinning to a commit SHA is the fix, and the failure mode of
// forgetting is silent, so it is checked rather than remembered.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	usesLine = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)`)
	shaPin   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func TestEveryActionIsPinnedToACommitSHA(t *testing.T) {
	// The workflows live at the repository root, one level above this module.
	dir := filepath.Join(repoRoot(t), "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for _, m := range usesLine.FindAllStringSubmatch(string(b), -1) {
			ref := m[1]
			// A local composite action (./.github/...) is this repo's own code.
			if strings.HasPrefix(ref, "./") {
				continue
			}
			checked++
			at := strings.LastIndex(ref, "@")
			if at < 0 || !shaPin.MatchString(ref[at+1:]) {
				t.Errorf("%s uses %q, which is a mutable reference. Pin it to a "+
					"40-character commit SHA (keep the version in a trailing comment). "+
					"These workflows can sign artifacts in the project's name.",
					e.Name(), ref)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no action references found; this check is not checking anything")
	}
}

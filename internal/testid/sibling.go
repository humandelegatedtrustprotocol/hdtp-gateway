package testid

// A test that holds a copy here to its source in a repository checked out beside this one, as the
// umbrella holds them (a fixture the cloud reads, the specification's table), reads it here.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// RequireSiblings is the variable that turns a sibling checkout's absence from a skip into a
// failure. The pre-push hook sets it to 1 (a guard that skips there has checked nothing), and to 0
// only when HDTP_ALLOW_MISSING_SIBLINGS=1 lets a push through without a checkout, after listing
// what will not be compared.
const RequireSiblings = "HDTP_REQUIRE_SIBLINGS"

// SiblingEnv names, for each sibling repository a guard reads, the variable that points at its
// checkout. scripts/sibling.sh reads the same names; TestTheTwoSiblingLocatorsAgree holds the two.
var SiblingEnv = map[string]string{
	"batondeck":     "HDTP_BATONDECK_DIR",
	"hdtp-identity": "HDTP_IDENTITY_DIR",
	"hdtp-spec":     "HDTP_SPEC_DIR",
}

// SiblingFile returns the bytes of rel, a slash-separated path inside the repository repo (found by
// SiblingDir, from this repository's top level whichever of its modules the test is in). When the checkout is not found the test is skipped, saying what goes unchecked, or
// fails when RequireSiblings is 1. When it is found and the file cannot be read, the test fails: a
// guard that skipped on any missing file passed the day its file moved.
func SiblingFile(t testing.TB, repo, rel, unchecked string) []byte {
	t.Helper()
	dir, tried := SiblingDir(t, repo)
	if dir == "" {
		if os.Getenv(RequireSiblings) == "1" {
			t.Fatalf("%s is 1 and no %s checkout was found (tried %s; set %s to point at one), so %s",
				RequireSiblings, repo, strings.Join(tried, ", "), SiblingEnv[repo], unchecked)
		}
		t.Skipf("SKIPPED, and so %s: no %s checkout was found (tried %s; set %s to point at one)",
			unchecked, repo, strings.Join(tried, ", "), SiblingEnv[repo])
	}
	path := filepath.Join(dir, filepath.FromSlash(rel))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the %s checkout is at %s but %s cannot be read: %v", repo, dir, rel, err)
	}
	return b
}

// SiblingDir is where the checkout of repo is, and the places it looked. It returns "" when none
// of them is a directory.
func SiblingDir(t testing.TB, repo string) (string, []string) {
	t.Helper()
	env, ok := SiblingEnv[repo]
	if !ok {
		t.Fatalf("SiblingDir: %s has no variable in SiblingEnv", repo)
	}
	return siblingDir(nodeRoot(t), repo, os.Getenv(env))
}

func siblingDir(root, repo, override string) (string, []string) {
	candidates := siblingCandidates(root, repo, override, gitCommonDir(root))
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c, candidates
		}
	}
	return "", candidates
}

// The places a sibling may be, in order: the variable's value; the directory beside root, as the
// umbrella lays its repositories out (and as a worktree's sibling link does); and the directory
// beside the checkout git keeps this one's objects in, so a worktree anywhere finds the umbrella's.
// That checkout is the umbrella itself when the git directory is one of the umbrella's modules
// (`<umbrella>/.git/modules/<name>`), and the main checkout when it is that checkout's `.git`.
func siblingCandidates(root, repo, override, common string) []string {
	var out []string
	add := func(c string) {
		if c != "" && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	add(override)
	add(filepath.Join(filepath.Dir(root), repo))
	if m := umbrellaModule.FindStringSubmatch(filepath.ToSlash(common)); m != nil {
		add(filepath.Join(filepath.FromSlash(m[1]), repo))
	} else if filepath.Base(common) == ".git" {
		add(filepath.Join(filepath.Dir(filepath.Dir(common)), repo))
	}
	return out
}

var umbrellaModule = regexp.MustCompile(`^(.*)/\.git/modules/[^/]+$`)

// gitCommonDir is root's git directory shared by all its worktrees, or "" outside git. A hook in a
// linked worktree exports GIT_DIR and its siblings, so they are taken out of git's environment:
// the question is about root, not about whatever repository the caller's hook was run for.
func gitCommonDir(root string) string {
	cmd := exec.Command("git", "-C", root, "rev-parse", "--path-format=absolute", "--git-common-dir")
	cmd.Env = withoutGitEnv(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func withoutGitEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GIT_") {
			out = append(out, kv)
		}
	}
	return out
}

// nodeModule is this repository's root module. The harness is a module of its own inside it, and
// its tests read siblings too, so the root is found by name rather than as the nearest go.mod.
const nodeModule = "github.com/humandelegatedtrustprotocol/hdtp-gateway"

var moduleLine = regexp.MustCompile(`(?m)^module\s+(\S+)\s*$`)

// nodeRoot is the nearest directory upward from the test's working directory whose go.mod declares
// nodeModule: the repository's top level, from the node's packages and the harness's alike.
func nodeRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if b, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if m := moduleLine.FindSubmatch(b); m != nil && string(m[1]) == nodeModule {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod declaring %s above the test's directory", nodeModule)
		}
		dir = parent
	}
}

package integrationtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

var siblingRepos = []string{"batondeck", "hdtp-identity", "hdtp-spec"}

var siblingVars = map[string]string{
	"batondeck":     "HDTP_BATONDECK_DIR",
	"hdtp-identity": "HDTP_IDENTITY_DIR",
	"hdtp-spec":     "HDTP_SPEC_DIR",
}

const dependentsLine = "Makefile dependents: the cloud's conformance battery is not compiled or seal-tested against this change"

// siblingCall is one testid.SiblingFile call: the file it is in, the repository it reads and what
// goes unchecked without it.
type siblingCall struct{ file, repo, unchecked string }

// siblingCalls parses every Go file of the repository and returns its testid.SiblingFile calls.
// Each must name its repository and what goes unchecked as string literals, or the hook could not
// say what a missing sibling costs.
func siblingCalls(t *testing.T, root string) []siblingCall {
	t.Helper()
	var calls []siblingCall
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SiblingFile" {
				return true
			}
			if len(call.Args) != 4 {
				t.Errorf("%s: SiblingFile with %d arguments", rel, len(call.Args))
				return true
			}
			repo, err1 := literal(call.Args[1])
			unchecked, err2 := literal(call.Args[3])
			if err1 != nil || err2 != nil {
				t.Errorf("%s: SiblingFile's repository and what goes unchecked must be string literals", rel)
				return true
			}
			calls = append(calls, siblingCall{filepath.ToSlash(rel), repo, unchecked})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 {
		t.Fatal("no testid.SiblingFile call found; the reader is broken")
	}
	return calls
}

func literal(e ast.Expr) (string, error) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", strconv.ErrSyntax
	}
	return strconv.Unquote(lit.Value)
}

// notRun is what scripts/sibling-guards.sh must print for repo: one line per call, and the
// Makefile's dependents for batondeck.
func notRun(calls []siblingCall, repo string) []string {
	var out []string
	for _, c := range calls {
		if c.repo == repo {
			out = append(out, c.file+": "+c.unchecked)
		}
	}
	sort.Strings(out)
	if repo == "batondeck" {
		out = append(out, dependentsLine)
	}
	return out
}

func gitless(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GIT_") {
			out = append(out, kv)
		}
	}
	return out
}

// The hook names what a push without a sibling does not compare from scripts/sibling-guards.sh,
// which reads the code with grep. Here the Go parser reads the same calls, both directions: a call
// the grep cannot see (split over lines, a repository in a variable) would go unlisted.
func TestTheSiblingGuardsListIsTheCode(t *testing.T) {
	root := repoRoot(t)
	calls := siblingCalls(t, root)
	for _, repo := range siblingRepos {
		out, err := exec.Command("sh", filepath.Join(root, "scripts", "sibling-guards.sh"), root, repo).Output()
		if err != nil {
			t.Fatalf("scripts/sibling-guards.sh %s: %v", repo, err)
		}
		got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if want := notRun(calls, repo); !slices.Equal(got, want) {
			t.Errorf("scripts/sibling-guards.sh %s prints\n  %s\nthe code's SiblingFile calls say\n  %s",
				repo, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
	mk := readDoc(t, root, "Makefile")
	if !strings.Contains(mk, "CLOUD_BATTERY := $(if $(BATONDECK)") {
		t.Error("the Makefile's dependents no longer reads the batondeck checkout; scripts/sibling-guards.sh says it does")
	}
}

// The parser skips dot-directories and node_modules; so must the grep. A checkout with a worktree
// under .claude/worktrees holds a second copy of every call, and the grep listed each twice.
func TestTheSiblingGuardsListSkipsWhatTheParserSkips(t *testing.T) {
	root := repoRoot(t)
	calls := siblingCalls(t, root)
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, under := range []string{"", ".claude/worktrees/copy/", "web/node_modules/copy/"} {
		for _, rel := range append([]string{"scripts/sibling-guards.sh"}, callFiles(calls)...) {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(tmp, filepath.FromSlash(under+rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, b, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	tmpCalls := siblingCalls(t, tmp)
	if len(tmpCalls) != len(calls) {
		t.Fatalf("the parser found %d calls in the copy, %d in the repository", len(tmpCalls), len(calls))
	}
	for _, repo := range siblingRepos {
		out, err := exec.Command("sh", filepath.Join(tmp, "scripts", "sibling-guards.sh"), tmp, repo).Output()
		if err != nil {
			t.Fatalf("scripts/sibling-guards.sh %s: %v", repo, err)
		}
		got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		if want := notRun(tmpCalls, repo); !slices.Equal(got, want) {
			t.Errorf("with copies under .claude/ and node_modules/, scripts/sibling-guards.sh %s prints\n  %s\nthe parser says\n  %s",
				repo, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
}

// callFiles is each file that holds a call, once.
func callFiles(calls []siblingCall) []string {
	var files []string
	for _, c := range calls {
		if !slices.Contains(files, c.file) {
			files = append(files, c.file)
		}
	}
	return files
}

// The pre-push hook's three answers to the sibling checkouts, run on the real hook in a repository
// built for the run, with make and docker stubbed (the stub make records each step and the
// HDTP_REQUIRE_SIBLINGS it ran under): every sibling present runs the gate requiring them; one
// missing refuses the push before anything runs, naming each and its variable; missing with
// HDTP_ALLOW_MISSING_SIBLINGS=1 runs the gate not requiring them, after listing first, one line
// each, every comparison that will not run.
func TestThePrePushHookOnMissingSiblings(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is not on PATH: %v", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is not on PATH: %v", err)
	}
	root := repoRoot(t)
	calls := siblingCalls(t, root)

	run := func(t *testing.T, present bool, optOut string) (out string, code int, makes []string) {
		t.Helper()
		tmp, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		node := filepath.Join(tmp, "node")
		copyIn := func(rel string) {
			t.Helper()
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(node, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, b, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for _, rel := range []string{"githooks/pre-push", "scripts/sibling.sh", "scripts/sibling-guards.sh"} {
			copyIn(rel)
		}
		for _, c := range calls {
			copyIn(c.file)
		}
		if present {
			for _, repo := range siblingRepos {
				if err := os.MkdirAll(filepath.Join(tmp, repo), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		bin := filepath.Join(tmp, "bin")
		log := filepath.Join(tmp, "make.log")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		stubs := map[string]string{
			"make":   "#!/bin/sh\necho \"$1 ${HDTP_REQUIRE_SIBLINGS-unset}\" >>\"$STUB_MAKE_LOG\"\necho \"stub make $1\"\n",
			"docker": "#!/bin/sh\n[ \"$1\" = port ] && echo 127.0.0.1:5432\nexit 0\n",
		}
		for name, body := range stubs {
			if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		env := gitless(os.Environ())
		for _, v := range []string{"HDTP_BATONDECK_DIR", "HDTP_IDENTITY_DIR", "HDTP_SPEC_DIR", "HDTP_REQUIRE_SIBLINGS", "HDTP_PREPUSH_LIVE", "HDTP_TEST_POSTGRES_DSN"} {
			env = append(env, v+"=")
		}
		env = append(env, "HDTP_ALLOW_MISSING_SIBLINGS="+optOut, "STUB_MAKE_LOG="+log, "PATH="+bin+":"+os.Getenv("PATH"))
		git := func(args ...string) string {
			t.Helper()
			cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
			cmd.Env = env
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, b)
			}
			return strings.TrimSpace(string(b))
		}
		git("init", "-q", node)
		git("-C", node, "add", "-A")
		git("-C", node, "commit", "-q", "-m", "x")
		head := git("-C", node, "rev-parse", "HEAD")

		cmd := exec.Command("bash", filepath.Join(node, "githooks", "pre-push"), "origin", "https://example.invalid/node.git")
		cmd.Dir = node
		cmd.Env = env
		cmd.Stdin = strings.NewReader("refs/heads/x " + head + " refs/heads/x " + head + "\n")
		b, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if l, err := os.ReadFile(log); err == nil {
			makes = strings.Split(strings.TrimRight(string(l), "\n"), "\n")
		}
		return string(b), code, makes
	}
	steps := func(t *testing.T, makes []string, want string) {
		t.Helper()
		if len(makes) < 6 {
			t.Fatalf("the stub make ran %d times (%q); the hook did not run its gate", len(makes), makes)
		}
		for _, m := range makes {
			if !strings.HasSuffix(m, " "+want) {
				t.Errorf("make %s ran with HDTP_REQUIRE_SIBLINGS=%s, want %s", strings.Fields(m)[0], strings.Fields(m)[1], want)
			}
		}
	}

	t.Run("every sibling present: the gate requires them", func(t *testing.T) {
		out, code, makes := run(t, true, "")
		if code != 0 {
			t.Fatalf("the hook exited %d:\n%s", code, out)
		}
		steps(t, makes, "1")
		if strings.Contains(out, "NOT RUN") {
			t.Errorf("the hook lists comparisons as not run with every sibling present:\n%s", out)
		}
	})

	t.Run("a sibling missing: the push is refused, naming each", func(t *testing.T) {
		out, code, makes := run(t, false, "")
		if code == 0 {
			t.Fatalf("the hook let a push through with no sibling checkout:\n%s", out)
		}
		if len(makes) != 0 {
			t.Errorf("the hook ran make %q before refusing", makes)
		}
		for _, repo := range siblingRepos {
			if !strings.Contains(out, "no "+repo+" checkout was found") || !strings.Contains(out, siblingVars[repo]) {
				t.Errorf("the refusal does not name %s and %s:\n%s", repo, siblingVars[repo], out)
			}
		}
		if !strings.Contains(out, "HDTP_ALLOW_MISSING_SIBLINGS=1") {
			t.Errorf("the refusal does not say how to push without them:\n%s", out)
		}
	})

	t.Run("a sibling missing, HDTP_ALLOW_MISSING_SIBLINGS=1: the gate runs after the list", func(t *testing.T) {
		out, code, makes := run(t, false, "1")
		if code != 0 {
			t.Fatalf("the hook exited %d:\n%s", code, out)
		}
		steps(t, makes, "0")
		first := strings.Index(out, "stub make ")
		if first < 0 {
			t.Fatalf("no make step in the hook's output:\n%s", out)
		}
		listed := 0
		for _, repo := range siblingRepos {
			for _, line := range notRun(calls, repo) {
				want := "pre-push: !! NOT RUN (no " + repo + " checkout) " + line + "\n"
				at := strings.Index(out, want)
				if at < 0 {
					t.Errorf("the hook does not list %q:\n%s", strings.TrimSpace(want), out)
				} else if at > first {
					t.Errorf("the hook lists %q after the gate started", strings.TrimSpace(want))
				}
				listed++
			}
		}
		if got := strings.Count(out, "NOT RUN"); got != listed {
			t.Errorf("the hook lists %d comparisons as not run; the code makes %d", got, listed)
		}
	})
}

// A guard whose checkout is not found skips, and `go test` without -v prints no skip: under a bare
// `make check` a missing checkout went unsaid. `dependents`, part of check, lists every comparison
// a missing checkout leaves unmade, the hook's list, unless HDTP_REQUIRE_SIBLINGS=1 makes those
// guards fail instead. Run on the real Makefile in a tree built for the run, with go stubbed.
func TestMakeCheckListsWhatAMissingCheckoutLeavesUnchecked(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Fatalf("make is not on PATH: %v", err)
	}
	root := repoRoot(t)
	calls := siblingCalls(t, root)

	run := func(t *testing.T, present bool, require string) (string, int) {
		t.Helper()
		tmp, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		node := filepath.Join(tmp, "node")
		for _, rel := range append([]string{"Makefile", "go.mod", "scripts/sibling.sh", "scripts/sibling-guards.sh"}, callFiles(calls)...) {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(node, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, b, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(node, "harness"), 0o755); err != nil {
			t.Fatal(err)
		}
		if present {
			for _, repo := range siblingRepos {
				if err := os.MkdirAll(filepath.Join(tmp, repo, "gateway", "conformance"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		bin := filepath.Join(tmp, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		env := gitless(os.Environ())
		for _, v := range testid.SiblingEnv {
			env = append(env, v+"=")
		}
		env = append(env, "HDTP_REQUIRE_SIBLINGS="+require, "PATH="+bin+":"+os.Getenv("PATH"))
		cmd := exec.Command("make", "-s", "dependents")
		cmd.Dir = node
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(b), code
	}

	t.Run("no checkout: each comparison is listed", func(t *testing.T) {
		out, code := run(t, false, "")
		if code != 0 {
			t.Fatalf("make dependents exited %d:\n%s", code, out)
		}
		listed := 0
		for _, repo := range siblingRepos {
			for _, line := range notRun(calls, repo) {
				if want := "!! NOT RUN (no " + repo + " checkout) " + line + "\n"; !strings.Contains(out, want) {
					t.Errorf("make dependents does not list %q:\n%s", strings.TrimSpace(want), out)
				}
				listed++
			}
		}
		if got := strings.Count(out, "NOT RUN"); got != listed {
			t.Errorf("make dependents lists %d comparisons as not run; the code makes %d:\n%s", got, listed, out)
		}
	})
	t.Run("every checkout: nothing is listed", func(t *testing.T) {
		out, code := run(t, true, "")
		if code != 0 {
			t.Fatalf("make dependents exited %d:\n%s", code, out)
		}
		if strings.Contains(out, "NOT RUN") {
			t.Errorf("make dependents lists comparisons as not run with every checkout present:\n%s", out)
		}
	})
	t.Run("no checkout, HDTP_REQUIRE_SIBLINGS=1: it fails, and lists nothing", func(t *testing.T) {
		out, code := run(t, false, "1")
		if code == 0 {
			t.Fatalf("make dependents passed with HDTP_REQUIRE_SIBLINGS=1 and no batondeck checkout:\n%s", out)
		}
		if strings.Contains(out, "NOT RUN") {
			t.Errorf("make dependents lists comparisons as not run where they fail:\n%s", out)
		}
	})
}

package testid

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The sibling checkouts are found by two copies of one rule: SiblingDir for the Go guards and
// scripts/sibling.sh for the Makefile's `dependents`. Both are run here on the same layouts, built in
// a temporary directory with real git, and must give the same answer, the expected one: a variable,
// the directory beside, a worktree finding the main checkout's sibling, a checkout whose git
// directory is one of an umbrella's modules finding the umbrella's, and nothing.
func TestTheTwoSiblingLocatorsAgree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git is not on PATH: %v", err)
	}
	script := filepath.Join(moduleRoot(t), "scripts", "sibling.sh")
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := func(rel string) string { return filepath.Join(tmp, filepath.FromSlash(rel)) }
	for _, d := range []string{"ws/batondeck", "else", "umb/batondeck", "umb/.git/modules", "other", "beside/batondeck", "beside/node", "lone/node", "env/spec"} {
		if err := os.MkdirAll(at(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
		cmd.Env = withoutGitEnv(os.Environ())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q", at("ws/main"))
	git("-C", at("ws/main"), "commit", "-q", "--allow-empty", "-m", "x")
	git("-C", at("ws/main"), "worktree", "add", "-q", at("else/wt"))
	git("init", "-q", "--separate-git-dir="+at("umb/.git/modules/node"), at("other/node"))

	cases := []struct {
		name, root, repo, override, want string
	}{
		{"the variable", at("lone/node"), "hdtp-spec", at("env/spec"), at("env/spec")},
		{"the directory beside", at("beside/node"), "batondeck", "", at("beside/batondeck")},
		{"a worktree finds its main checkout's sibling", at("else/wt"), "batondeck", "", at("ws/batondeck")},
		{"an umbrella's module finds the umbrella's", at("other/node"), "batondeck", "", at("umb/batondeck")},
		{"the variable wins over the directory beside", at("beside/node"), "batondeck", at("env/spec"), at("env/spec")},
		{"a variable naming nothing falls through", at("beside/node"), "batondeck", at("env/none"), at("beside/batondeck")},
		{"nothing", at("lone/node"), "batondeck", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			goAnswer, _ := siblingDir(c.root, c.repo, c.override)
			cmd := exec.Command("sh", script, c.root, c.repo)
			env := withoutGitEnv(os.Environ())
			for _, v := range SiblingEnv {
				env = append(env, v+"=")
			}
			cmd.Env = append(env, SiblingEnv[c.repo]+"="+c.override)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("scripts/sibling.sh %s: %v", c.repo, err)
			}
			shAnswer := strings.TrimSpace(string(out))
			if goAnswer != c.want {
				t.Errorf("SiblingDir answers %q, want %q", goAnswer, c.want)
			}
			if filepath.Clean(shAnswer) != c.want && !(shAnswer == "" && c.want == "") {
				t.Errorf("scripts/sibling.sh answers %q, want %q", shAnswer, c.want)
			}
		})
	}
}

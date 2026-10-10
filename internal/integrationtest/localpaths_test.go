package integrationtest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// homeDir is a home directory on macOS or Linux: the shape githooks/commit-msg refuses in a message.
// A /home path counts where it begins a path (not inside one, as in a route like a/home/x) and names
// someone, whatever follows the name. The patterns and plants in this file are spelled in halves so
// that it does not carry what it refuses.
const homeDir = "(?m)/Users" + "/|(^|[^A-Za-z0-9_/-])/home" + "/[A-Za-z0-9._-]+([/\"'`]|[[:space:]]|$)"

// No tracked text may carry a path from the machine that wrote it.
//
// `docs/harness-fabric-notes.md` shipped with a subagent's scratchpad path as its first line, and
// sat there unreferenced because it was an intermediate whose edits had already been folded into
// harness-design.md. In a public repository that is a stranger reading someone's home directory
// layout, and it is the kind of thing nobody greps for until it is already published.
//
// Four shapes: a home directory on macOS or Linux (a path under /Users or /home, whatever the
// name), an agent scratchpad and an agent job directory. Every tracked file is read, whatever its
// extension, except what git itself would call binary (a NUL byte in the first 8000 bytes) and
// third_party/, which is upstream's text. A frozen record of docs/records.sha256 is left alone while
// its bytes are the manifest's: a record says what was true on its day, and PLAN.md, one of them,
// names an invented /home path in describing an earlier, narrower form of this test. The commit-msg
// hook (githooks/commit-msg) holds a commit MESSAGE to the same rule, which this test cannot see.
func TestNoTrackedFileLeaksALocalPath(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	leak := regexp.MustCompile(homeDir + `|/private` + `/tmp/claude|\.claude/(jobs|projects)/`)
	frozen := frozenRecords(t, root)

	var checked int
	for _, rel := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if rel == "" || strings.HasPrefix(rel, "third_party/") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(root, rel))
		if rerr != nil {
			continue // deleted between ls-files and now
		}
		head := b
		if len(head) > 8000 {
			head = head[:8000]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			continue // binary, as git decides it
		}
		if sum, listed := frozen[rel]; listed && fmt.Sprintf("%x", sha256.Sum256(b)) == sum {
			continue
		}
		checked++
		for i, line := range strings.Split(string(b), "\n") {
			if m := leak.FindString(line); m != "" {
				t.Errorf("%s:%d carries a local machine path (%q). It would ship to whoever clones this.", rel, i+1, m)
			}
		}
	}
	if checked < 100 {
		t.Fatalf("checked %d files; this lint is checking too little", checked)
	}
	t.Logf("checked %d tracked text files", checked)
}

// The hook and homeDir are two copies of one rule: each planted message is judged by both. git keeps
// comment lines and everything under a scissors line in a message given with -m or -F, so a path
// there is refused like any other.
func TestCommitMsgHookRefusesWhatTheTreeRefuses(t *testing.T) {
	root := repoRoot(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash unavailable: %v", err)
	}
	home := regexp.MustCompile(homeDir)
	scissors := "# ------------------------ >8 ------------------------"
	mac, linux, bare := "/Users"+"/alina/x", "/home"+"/alina/x", "cd /home"+"/alina"
	cases := []struct {
		name, msg string
		refused   bool
	}{
		{"a macOS home", "Fix\n\nbuilt in " + mac + "\n", true},
		{"a Linux home", "Fix\n\nbuilt in " + linux + "\n", true},
		{"a Linux home with no trailing slash", "Fix\n\n" + bare + "\n", true},
		{"a path in a comment line", "Fix\n\nbuilt in the worktree\n# " + mac + "\n", true},
		{"a path under the scissors", "Fix\n\nbuilt in the worktree\n" + scissors + "\n" + linux + "\n", true},
		{"no path", "Fix\n\nbuilt in the worktree\n", false},
		{"a route with home inside it", "Fix\n\nthe route /a/home" + "/mcp\n", false},
		{"a bare /home prefix", "Fix\n\nconcat('/home" + "/', name)\n", false},
	}
	for _, c := range cases {
		f := filepath.Join(t.TempDir(), "COMMIT_EDITMSG")
		if err := os.WriteFile(f, []byte(c.msg), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", filepath.Join("githooks", "commit-msg"), f)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("%s: the hook did not run: %v", c.name, err)
		}
		if refused := err != nil; refused != c.refused {
			t.Errorf("%s: the hook refused=%v, want %v\n%s", c.name, refused, c.refused, out)
		}
		if matched := home.MatchString(c.msg); matched != c.refused {
			t.Errorf("%s: homeDir matched=%v, want %v", c.name, matched, c.refused)
		}
	}
}

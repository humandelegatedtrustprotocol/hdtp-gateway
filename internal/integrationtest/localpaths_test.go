package integrationtest

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
	leak := regexp.MustCompile(`/Users/|/home/[A-Za-z0-9._-]+/|/private/tmp/claude|\.claude/(jobs|projects)/`)
	self := "localpaths_test.go"
	frozen := frozenRecords(t, root)

	var checked int
	for _, rel := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if rel == "" || strings.HasPrefix(rel, "third_party/") {
			continue
		}
		if filepath.Base(rel) == self {
			continue // this file names the patterns; it is describing them, not leaking
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

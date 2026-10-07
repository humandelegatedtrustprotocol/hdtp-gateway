package integrationtest

// The README quickstart is the first thing a new owner does, and it was broken in
// three separate ways at once — none of which any test could see, because nothing
// compared the documented commands against what the image and compose file
// actually provide:
//
//   1. the image could not build at all (P14-03a);
//   2. `docker compose up` published no port, and the portal bound the CONTAINER's
//      loopback, so the URL it printed was unreachable even with `-p` (E12);
//   3. `docker compose exec hdtp-gateway hdtp-gateway …` — the README's own next
//      command — failed with "executable file not found in $PATH".
//
// These are the cheap structural halves. The expensive half is the harness
// standing the whole thing up and driving the wizard in a browser.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestQuickstartCommandsAreServedByTheImageAndCompose(t *testing.T) {
	root := repoRoot(t)

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}

	// (a) If the README tells the owner to exec a BARE command name, that name has
	// to resolve on the image's PATH. /hdtp-gateway alone does not.
	bareExec := regexp.MustCompile(`docker compose exec \S+ (\w[\w-]*)`)
	for _, m := range bareExec.FindAllStringSubmatch(string(readme), -1) {
		name := m[1]
		if strings.HasPrefix(name, "/") {
			continue
		}
		if !strings.Contains(string(dockerfile), "/usr/local/bin/"+name) {
			t.Errorf("README runs `docker compose exec … %s` but the image does not place "+
				"%q on PATH — the documented command fails with "+
				"\"executable file not found in $PATH\"", name, name)
		}
	}

	// (b) The README tells the owner to open the portal URL the log prints, so compose has to
	// publish it.
	if !strings.Contains(string(readme), "The log prints your portal URL") {
		t.Error("README no longer says the log prints the portal URL where this test reads it")
	}
	if !strings.Contains(string(compose), "127.0.0.1:8080:") {
		t.Error("the README tells the owner to open the portal URL, but compose publishes " +
			"nothing on host loopback — `docker compose up` prints a URL that cannot be reached")
	}

	// (c) …and only on loopback. The portal is plain HTTP in compose, which SPEC §8.3 allows on
	// loopback only; publishing "8080:8080" would put the setup wizard and the sign-in,
	// unencrypted, on the owner's whole LAN.
	if regexp.MustCompile(`(?m)^\s*-\s*"?8080:`).Match(compose) {
		t.Error("compose publishes the portal on ALL interfaces; it is plain HTTP, which SPEC §8.3 " +
			"allows on loopback only, so this would expose it to the LAN. Bind it to 127.0.0.1 only")
	}
}

// No tracked file may carry a path from the machine that wrote it.
//
// `docs/harness-fabric-notes.md` shipped with a subagent's scratchpad path as
// its first line — "The design is durable at /private/tmp/claude-501/…" — and
// sat there unreferenced because it was an intermediate whose edits had already
// been folded into harness-design.md. In a public repository that is a stranger
// reading someone's home directory layout, and it is the kind of thing nobody
// greps for until it is already published.
func TestNoTrackedFileLeaksALocalPath(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	// Deliberately narrow. `/home/me/nodeA` in a table-driven test is invented
	// fixture data, not a leak, and a pattern broad enough to catch it flags
	// honest tests forever. These three shapes are what actually escapes: a
	// macOS home directory, an agent scratchpad, and an agent job directory.
	leak := regexp.MustCompile(`/Users/[a-z]|/private/tmp/claude|\.claude/(jobs|projects)/`)
	self := "quickstart_test.go"

	var checked int
	for _, rel := range strings.Fields(string(out)) {
		switch filepath.Ext(rel) {
		case ".md", ".go", ".yml", ".yaml", ".json", ".sh", ".ts", ".tsx", ".css":
		default:
			continue
		}
		if strings.HasSuffix(rel, self) {
			continue // this file names the patterns; it is describing them, not leaking
		}
		b, rerr := os.ReadFile(filepath.Join(root, rel))
		if rerr != nil {
			continue // deleted between ls-files and now
		}
		checked++
		for i, line := range strings.Split(string(b), "\n") {
			if m := leak.FindString(line); m != "" {
				t.Errorf("%s:%d carries a local machine path (%q). It would ship to "+
					"whoever clones this.", rel, i+1, m)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no files checked; this lint is checking nothing")
	}
	t.Logf("checked %d tracked text files", checked)
}

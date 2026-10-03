package integrationtest

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// PACT 1.x is gone, and this is what holds it gone: no tracked file of this repository (the
// node) carries a NAME that 1.x had and 2.x does not — a card property, a flag, a mode, a
// tool, a column, a table, an audit action, an event, an identifier — outside the three kinds of
// file that are allowed to:
//
//   - an append-only migration, which cannot be edited and records what the schema once was;
//   - a dated record (`docs/release/`, the build log in `PLAN.md`), which says what was true then;
//   - a file listed below WITH ITS REASON: a test that feeds 1.x IN to prove it is refused.
//
// A comment is not exempt. "Which is why the retired X-PACT-… is gone" keeps the name greppable
// for ever, and the sentence survives without it. The generation's own name is not forbidden —
// the specification has to say "PACT 1.x is not supported" — and neither is saying WHY code has
// the shape it has. What this proves is narrower and checkable: run the grep, and everything it
// returns is a refusal, a migration or a dated record.
//
// The names are in testdata/pact1x-markers.txt. pact-cloud and pact-protocol are their own
// repositories and carry their own guard and their own copy of that file; when they are checked
// out beside this one (the umbrella's layout), their copies must be these bytes.
func TestNoTrackedFileCarriesAOneXName(t *testing.T) {
	root := repoRoot(t)
	beside := filepath.Dir(root)
	markers, raw := loadMarkers(t, filepath.Join(root, "internal", "integrationtest", "testdata", "pact1x-markers.txt"))

	// History by construction: never scanned.
	history := regexp.MustCompile(`^(migrations/|docs/release/|PLAN\.md$)`)
	// Generated or vendored: what they hold is decided elsewhere.
	built := regexp.MustCompile(`(^|/)(dist|node_modules|target)/|package-lock\.json$|\.(png|jpg|jpeg|gif|ico|pdf|wasm|woff2?|gz|tar|db|sum)$`)

	allowed := map[string]string{
		"internal/contacts/vcard_test.go":              "feeds 1.x cards to the parser to prove intake refuses them and that a 2.x card ignores the retired properties",
		"internal/contacts/testdata/iphone-export.vcf": "a phone's export of a 1.x card, the input of the refusal above",
		"internal/contacts/displayname_test.go":        "a 1.x card as the input of a refusal",
		"internal/cli/offer_test.go":                   "an invite offer carrying a 1.x card must be refused",
		"internal/cli/offer_fuzz_test.go":              "a 1.x card in the fuzz corpus of the same refusal",
		"internal/internalui/chrome_test.go":           "asserts the portal never shows the retired card properties to a person",
		"internal/node/node_test.go":                   "asserts the relay's route answers 404 and the invite landing names no retired property",
		"internal/internalui/ownermcp/server_test.go":  "asserts the contact sweep's tool is not offered",
	}

	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Skipf("SKIPPED, and so clearance is unchecked: git is unavailable (%v)", err)
	}
	carries := map[string]bool{}
	var found []string
	scanned := 0
	for _, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// The list is patterns, not names, and is compared byte for byte below instead.
		if rel == "" || history.MatchString(rel) || built.MatchString(rel) || filepath.Base(rel) == "pact1x-markers.txt" {
			continue
		}
		// A path that is gone was deleted between ls-files and now.
		if st, err := os.Stat(filepath.Join(root, rel)); err != nil || st.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		scanned++
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for line := 1; sc.Scan(); line++ {
			if bytes.IndexByte(sc.Bytes(), 0) >= 0 {
				break // binary
			}
			for _, m := range markers {
				if hit := m.FindString(sc.Text()); hit != "" {
					carries[rel] = true
					if _, ok := allowed[rel]; !ok {
						found = append(found, rel+":"+strconv.Itoa(line)+": "+hit)
					}
					break
				}
			}
		}
		_ = f.Close()
	}
	// A guard that read nothing passes. This tree has about 550 tracked files of text outside its
	// migrations and records; the floor is there to catch a walk that broke, not to track the count.
	if scanned < 300 {
		t.Fatalf("scanned only %d files: the walk is broken, not the tree", scanned)
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("%d line(s) carry a name PACT 1.x had and 2.x does not. Remove the behaviour or say it without the "+
			"name; a test that feeds 1.x in to prove it is refused goes on the allow-list with its reason.\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
	for rel, why := range allowed {
		if !carries[rel] {
			t.Errorf("%s is allowed to carry a 1.x name (%s) and carries none: the list is stale", rel, why)
		}
	}

	// The siblings' copies of the list are these bytes.
	for _, sibling := range []string{"pact-cloud/gateway/scripts/pact1x-markers.txt", "pact-protocol/vectors/pact1x-markers.txt"} {
		theirs, err := os.ReadFile(filepath.Join(beside, sibling))
		if err != nil {
			t.Logf("not compared: %s is not checked out beside this repository", sibling)
			continue
		}
		if !bytes.Equal(theirs, raw) {
			t.Errorf("%s differs from this repository's list: one guard is looking for names the other is not", sibling)
		}
	}
}

func loadMarkers(t *testing.T, path string) ([]*regexp.Regexp, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*regexp.Regexp
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, regexp.MustCompile(line))
	}
	if len(out) < 10 {
		t.Fatalf("read only %d markers from %s: the reader is broken, not the tree", len(out), path)
	}
	return out, raw
}

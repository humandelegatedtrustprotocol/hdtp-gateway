package integrationtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The owner's rule, 2026-09-19: a pin is confirmed when it is needed, and the node does nothing
// proactively. PACT 2.1 §14.3 says the same of the protocol — a newer leaf arrives on use and needs
// no poll. The node polled anyway: `serve` re-fetched every contact's card two minutes after start
// and every six hours after, in original code that a first attempt at this rule walked straight
// past, because what it removed was a NAME it had itself given the interval.
//
// So this is a guard on the shape, not on a name. `node.SyncContacts` has one kind of caller — the
// owner MCP's `sync_contacts` tool, which is a person asking — and the wiring that hands it over.
// Anything else in the tree that mentions it is a way back to a timer.
func TestNothingSyncsContactsOnATimer(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]string{
		"internal/node/sync.go":                  "the definition",
		"internal/internalui/ownermcp/server.go": "the `sync_contacts` tool: on request, for one account",
		"internal/cli/compose.go":                "the wiring that hands the method to the owner MCP",
	}
	mention := regexp.MustCompile(`\bSyncContacts\b`)
	code := func(src string) string { // drop line comments: prose may name it, only code may not
		var out []string
		for _, line := range strings.Split(src, "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			out = append(out, line)
		}
		return strings.Join(out, "\n")
	}
	var seen int
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if !mention.MatchString(code(string(b))) {
				return nil
			}
			seen++
			rel, _ := filepath.Rel(root, path)
			if _, ok := allowed[filepath.ToSlash(rel)]; !ok {
				t.Errorf("%s calls or passes SyncContacts. The node does not sync contacts by itself: "+
					"the only caller is the owner MCP's `sync_contacts`, on request. If this is a new "+
					"on-request surface, add it here with the reason; if it is a timer, it is the thing "+
					"this test exists to stop.", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen != len(allowed) {
		t.Fatalf("expected SyncContacts in exactly %d files and found it in %d: the guard's own list is stale", len(allowed), seen)
	}
	// And in the files that may mention it, no timer stands near the mention. The owner MCP's
	// server does start one — its forwarder's idle check, two hundred lines from the tool — so this
	// looks at the neighbourhood of each timer rather than at the file: forty lines either side is
	// more than any goroutine here that a ticker drives.
	timer := regexp.MustCompile(`time\.(NewTicker|Tick|AfterFunc)\(`)
	for rel := range allowed {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(code(string(b)), "\n")
		for i, line := range lines {
			if !timer.MatchString(line) {
				continue
			}
			lo, hi := i-40, i+40
			if lo < 0 {
				lo = 0
			}
			if hi > len(lines) {
				hi = len(lines)
			}
			if mention.MatchString(strings.Join(lines[lo:hi], "\n")) {
				t.Errorf("%s:%d starts a timer within forty lines of SyncContacts: that is the shape this test exists to stop", rel, i+1)
			}
		}
	}
}

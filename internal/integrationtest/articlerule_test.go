package integrationtest

import (
	"regexp"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// The article before the name ("an", never "a") is refused by three gates, one per repository that
// writes the name: this Makefile's `names`, hdtp-identity's gate.sh and hdtp-spec's stated.mjs. Three
// copies of one rule drift the day one of them is edited, so this holds them to each other: the
// node's and the identity core's are the same POSIX pattern, byte for byte, and the specification's,
// a JavaScript literal, gives the same verdict as they do on every line of a corpus of hits and
// misses. The corpus spells the name through a placeholder, so this file is not a hit of its own.
func TestTheArticleRuleIsOneRuleInEveryRepository(t *testing.T) {
	root := repoRoot(t)

	node := patternIn(t, "Makefile", readDoc(t, root, "Makefile"), `(?m)^NAMES_ARTICLE := (.+)$`)
	gate := string(testid.SiblingFile(t, "hdtp-identity", "gate.sh", "the identity core's article rule is not compared with this one"))
	identity := patternIn(t, "hdtp-identity's gate.sh", gate, `(?s)step "The name takes \\"an\\"[^\n]*\n.*?git grep -n -I -E '([^']+)'`)
	stated := string(testid.SiblingFile(t, "hdtp-spec", "vectors/lib/stated.mjs", "the specification's article rule is not compared with this one"))
	spec := patternIn(t, "hdtp-spec's vectors/lib/stated.mjs", stated, `(?m)^export const ARTICLE = /(.+)/g$`)

	if node != identity {
		t.Errorf("the Makefile's NAMES_ARTICLE is\n\t%s\nand hdtp-identity's gate.sh refuses\n\t%s\nOne rule: change both in the same round.", node, identity)
	}

	const name = "\x00"
	hits := []string{
		"a \x00 node", "A \x00 envelope", "a `\x00` card", "a **\x00** card", "(a \x00 node)", "a X-\x00-VERSION line",
		"a \"\x00\" string", "a _\x00_ word", "> a \x00 node",
	}
	misses := []string{
		"an \x00 node", "data \x00", "banana \x00", "_a \x00", "1a \x00", "a HTTP node", "a node of \x00",
	}
	patterns := map[string]*regexp.Regexp{
		"the Makefile's NAMES_ARTICLE":   regexp.MustCompile(node),
		"hdtp-identity's gate.sh":        regexp.MustCompile(identity),
		"hdtp-spec's stated.mjs ARTICLE": regexp.MustCompile(spec),
	}
	for _, spelling := range []string{"HDTP", "hdtp"} {
		for where, re := range patterns {
			for _, line := range hits {
				if l := strings.ReplaceAll(line, name, spelling); !re.MatchString(l) {
					t.Errorf("%s does not refuse %q", where, l)
				}
			}
			for _, line := range misses {
				if l := strings.ReplaceAll(line, name, spelling); re.MatchString(l) {
					t.Errorf("%s refuses %q, which takes the right article", where, l)
				}
			}
		}
	}
}

// patternIn is the one submatch of expr in src, which must be there: a reader that finds nothing
// would compare nothing.
func patternIn(t *testing.T, where, src, expr string) string {
	t.Helper()
	m := regexp.MustCompile(expr).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s: the article pattern was not found (%s); the reader is broken or the rule moved", where, expr)
	}
	return m[1]
}

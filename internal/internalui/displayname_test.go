package internalui

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// The name shown for a contact is the FN from the card THAT CONTACT supplied. Two
// contacts may therefore carry the same name, and one of them may have chosen it
// on purpose: C cannot forge A's signature, but nothing stops C from calling
// itself "Alice" and being pinned under that label. Cryptographically the two are
// never confused -- they are different fingerprints and each message verifies
// against its own pinned key -- but a list that prints only the name shows the
// owner two identical rows.
func TestCollidingNamesCarryTheirFingerprint(t *testing.T) {
	alice := store.Contact{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaa", DisplayName: "Alice"}
	imposter := store.Contact{Fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbb", DisplayName: "alice "}
	bob := store.Contact{Fingerprint: "sha256:cccccccccccccccccccc", DisplayName: "Bob"}
	nameless := store.Contact{Fingerprint: "sha256:dddddddddddddddddddd"}

	got := labelContacts([]store.Contact{alice, imposter, bob, nameless})

	if got[bob.Fingerprint] != "Bob" {
		t.Errorf("an unambiguous name was decorated for no reason: %q", got[bob.Fingerprint])
	}
	if l := got[nameless.Fingerprint]; l != shortFpr(nameless.Fingerprint) {
		t.Errorf("a contact with no name rendered as %q rather than its fingerprint", l)
	}

	// Both sides of the collision must change. Decorating only the newcomer would
	// teach the owner that the plain "Alice" is the real one -- which is exactly
	// backwards the day the imposter is pinned first.
	for _, c := range []store.Contact{alice, imposter} {
		l := got[c.Fingerprint]
		if !strings.Contains(l, shortFpr(c.Fingerprint)) {
			t.Errorf("contact %s shares its name with another but renders as %q, "+
				"which is indistinguishable from the other one", c.Fingerprint, l)
		}
	}
	if got[alice.Fingerprint] == got[imposter.Fingerprint] {
		t.Errorf("two different contacts render identically as %q", got[alice.Fingerprint])
	}
}

// The defect this guards is not "these two templates were wrong" but "a name the
// peer chose was printed as the whole identity of a row". A third list would make
// the same mistake, so the rule is checked against the source rather than fixed
// twice: inside a {{range}} -- the only place two contacts appear together -- a
// DisplayName must be accompanied by a fingerprint the owner can actually SEE.
//
// Scope matters in both directions. Line-by-line, this both misses the contacts
// list (whose fingerprint is real but lives in an href, invisible) and flags the
// identity page (whose fingerprint is one line below, and whose names are the
// owner's own anyway). The block is the honest unit, and attribute values are not
// part of what a person reads.
func TestNoListRendersAPeerChosenNameAlone(t *testing.T) {
	dir := filepath.Join(repoRootUI(t), "internal", "internalui")
	opener := regexp.MustCompile(`\{\{-?\s*(range|if|with|define|block)\b`)
	closer := regexp.MustCompile(`\{\{-?\s*end\s*-?\}\}`)
	attr := regexp.MustCompile(`="[^"]*"`)

	type frame struct {
		kind  string
		start int
		lines []string
	}

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		var stack []*frame
		for i, line := range strings.Split(string(b), "\n") {
			for _, m := range opener.FindAllStringSubmatch(line, -1) {
				stack = append(stack, &frame{kind: m[1], start: i + 1})
			}
			for _, f := range stack {
				f.lines = append(f.lines, line)
			}
			for range closer.FindAllString(line, -1) {
				if len(stack) == 0 {
					continue
				}
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if f.kind != "range" {
					continue
				}
				body := strings.Join(f.lines, "\n")
				if !strings.Contains(body, ".DisplayName") {
					continue
				}
				if strings.Contains(attr.ReplaceAllString(body, ""), ".Fingerprint") {
					continue // shown as text the owner can read
				}
				t.Errorf("%s:%d ranges over contacts and prints a peer-chosen "+
					"DisplayName with no fingerprint the owner can SEE (one inside "+
					"an attribute does not count). Two contacts may carry the same "+
					"name, one of them deliberately. Render labelContacts' output.",
					filepath.Base(p), f.start)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Case folding is not enough, and the first version of labelContacts shipped as
// if it were. "Аlice" leads with U+0410 CYRILLIC CAPITAL A, which renders exactly
// like Latin "A" and case-folds to something else entirely -- so the two rows read
// identically and NEITHER was decorated. Comparison has to happen on a form where
// look-alikes have already collapsed.
func TestLookAlikeNamesCollideToo(t *testing.T) {
	genuine := store.Contact{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaa", DisplayName: "Alice"}

	for _, tc := range []struct {
		name    string
		fn      string
		collide bool
	}{
		{"one cyrillic letter", "Аlice", true},
		{"entirely cyrillic", "Аlісе", true},
		{"greek", "Αlice", true},
		{"fullwidth", "Ａlice", true},
		{"a genuinely different name", "Alicia", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := store.Contact{Fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbb", DisplayName: tc.fn}
			got := labelContacts([]store.Contact{genuine, other})
			decorated := strings.Contains(got[genuine.Fingerprint], shortFpr(genuine.Fingerprint))
			if decorated != tc.collide {
				verb := "was not"
				if decorated {
					verb = "was"
				}
				t.Errorf("%q vs %q: the genuine row %s decorated (rendered %q), want collide=%v",
					genuine.DisplayName, tc.fn, verb, got[genuine.Fingerprint], tc.collide)
			}
		})
	}
}

// Folding must not become a blunt instrument: two unrelated names in the same
// non-Latin script are not a collision, and treating them as one would decorate
// every row for owners who do not write in Latin.
func TestDistinctNonLatinNamesDoNotCollide(t *testing.T) {
	a := store.Contact{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaa", DisplayName: "सुमित"}
	b := store.Contact{Fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbb", DisplayName: "अनिल"}
	got := labelContacts([]store.Contact{a, b})
	if got[a.Fingerprint] != "सुमित" || got[b.Fingerprint] != "अनिल" {
		t.Errorf("two distinct names were treated as a collision: %q and %q",
			got[a.Fingerprint], got[b.Fingerprint])
	}
}

// The petname is the owner's own name for a contact, and the only name no peer
// can influence. It is OPTIONAL: most contacts will never have one, and the list
// must stay readable for them, so an absent petname simply falls back to the name
// the contact supplied.
func TestPetnameOverridesTheNameTheContactChose(t *testing.T) {
	c := store.Contact{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaa", DisplayName: "Alice", Petname: "Alice from work"}
	got := labelContacts([]store.Contact{c})
	if got[c.Fingerprint] != "Alice from work" {
		t.Errorf("petname ignored: rendered %q", got[c.Fingerprint])
	}
}

// Collision decoration exists to flag a name somebody ELSE chose. A petname that
// happens to match is the owner's own doing and needs no warning -- but the
// peer-chosen side of that collision still does, because that is the one that
// might have been chosen to match.
func TestOnlyThePeerChosenSideOfACollisionIsDecorated(t *testing.T) {
	mine := store.Contact{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaa", DisplayName: "A. Nakamura", Petname: "Alice"}
	theirs := store.Contact{Fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbb", DisplayName: "Alice"}
	got := labelContacts([]store.Contact{mine, theirs})

	if got[mine.Fingerprint] != "Alice" {
		t.Errorf("the owner's own petname was decorated: %q", got[mine.Fingerprint])
	}
	if !strings.Contains(got[theirs.Fingerprint], shortFpr(theirs.Fingerprint)) {
		t.Errorf("a peer-chosen name matching the owner's petname was not flagged: %q",
			got[theirs.Fingerprint])
	}
}

// Two petnames that match are entirely the owner's business. Decorating them
// would be nagging somebody about their own filing system.
func TestTwoPetnamesMayMatchWithoutComplaint(t *testing.T) {
	a := store.Contact{Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaa", DisplayName: "X", Petname: "Plumber"}
	b := store.Contact{Fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbb", DisplayName: "Y", Petname: "Plumber"}
	got := labelContacts([]store.Contact{a, b})
	if got[a.Fingerprint] != "Plumber" || got[b.Fingerprint] != "Plumber" {
		t.Errorf("the owner's own duplicate petnames were decorated: %q / %q",
			got[a.Fingerprint], got[b.Fingerprint])
	}
}

package internalui

import (
	"strings"

	"golang.org/x/text/secure/precis"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// labelContacts decides what to CALL each contact in a list.
//
// The name comes from the card the contact supplied, so it is theirs to choose.
// Choosing an existing contact's name is the one impersonation the protocol does
// not prevent: the envelope still verifies against the sender's own pinned key
// and is refused if it does not, so the two are never cryptographically confused
// -- but on screen they are two rows reading "Alice".
//
// So a name shared by more than one contact is not shown alone. Both sides carry
// their fingerprint, never just the newcomer: whichever was pinned first has no
// claim to the undecorated name, and decorating only the second one would teach
// the owner that the plain row is the trustworthy one.
func labelContacts(cs []store.Contact) map[string]string {
	// The name actually shown, and whether the OWNER chose it. A petname is the
	// one name no peer can influence, so it both wins and is exempt from the
	// warning below.
	type label struct {
		text string
		mine bool
	}
	eff := make(map[string]label, len(cs))
	seen := map[string]int{}
	for _, c := range cs {
		l := label{text: strings.TrimSpace(c.Petname), mine: true}
		if l.text == "" {
			l = label{text: strings.TrimSpace(c.DisplayName)}
		}
		eff[c.Fingerprint] = l
		if l.text != "" {
			seen[compareKey(l.text)]++
		}
	}

	out := make(map[string]string, len(cs))
	for _, c := range cs {
		l := eff[c.Fingerprint]
		switch {
		case l.text == "":
			out[c.Fingerprint] = shortFpr(c.Fingerprint)
		case !l.mine && seen[compareKey(l.text)] > 1:
			// Only the peer-chosen side is flagged. Two petnames that match are
			// the owner's own filing system; a peer-chosen name that matches
			// anything else is the case worth looking at, and the fingerprint is
			// what tells them apart.
			out[c.Fingerprint] = l.text + " · " + shortFpr(c.Fingerprint)
		default:
			out[c.Fingerprint] = l.text
		}
	}
	return out
}

// compareKey reduces a name to the form two names are compared IN. Case folding
// alone is what the first version of this did, and one Cyrillic letter walked
// straight through it: "\u0410lice" renders as "Alice" and folds to neither.
//
// RFC 8266 (PRECIS Nickname) does the boring half properly -- case, whitespace,
// width, and NFKC -- which is more than the hand-rolled version managed; it folded
// case but not fullwidth. PRECIS deliberately stops short of look-alikes, so the
// script fold below is layered on top.
func compareKey(s string) string {
	k, err := precis.Nickname.CompareKey(s)
	if err != nil {
		// A name PRECIS refuses is still a name somebody will read. Fall back to
		// the crude form rather than treating it as nameless.
		k = strings.ToLower(strings.Join(strings.Fields(s), " "))
	}
	return lookAlikes.Replace(k)
}

// lookAlikes collapses the cross-script characters that a reader cannot tell from
// a Latin letter, which is where this attack actually lives: an impostor does not
// need a name that IS yours, only one that looks like it in a list. Inputs are
// already case-folded by PRECIS, so only lowercase forms appear here.
//
// It is deliberately not the full UTS #39 confusables table. That table also
// equates within-Latin pairs -- l/I/1, O/0, rn/m -- which would collide "Ali" with
// "All" and decorate honest rows for everyone. Cross-script is the high-value,
// low-false-positive half. Within-Latin look-alikes remain a known gap.
var lookAlikes = strings.NewReplacer(
	// Cyrillic
	"\u0430", "a", "\u0432", "b", "\u0435", "e", "\u043a", "k", "\u043c", "m",
	"\u043d", "h", "\u043e", "o", "\u0440", "p", "\u0441", "c", "\u0442", "t",
	"\u0443", "y", "\u0445", "x", "\u0455", "s", "\u0456", "i", "\u0458", "j",
	"\u04bb", "h", "\u04cf", "l", "\u0501", "d",
	// Greek
	"\u03b1", "a", "\u03b2", "b", "\u03b5", "e", "\u03b9", "i", "\u03ba", "k",
	"\u03bd", "v", "\u03bf", "o", "\u03c1", "p", "\u03c4", "t", "\u03c5", "u",
	"\u03c7", "x", "\u03f2", "c",
)

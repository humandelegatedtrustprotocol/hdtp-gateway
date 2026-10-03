package contacts

import (
	"strings"
	"testing"
)

// A peer's FN is the string the owner READS to decide who is talking to them, and
// the peer chooses it. It arrives inside a card capped only at 16KiB, so before
// this it could be a paragraph, could carry control characters, and could carry a
// bidi override that visually reverses whatever is rendered after it. ParseCard is
// the single gate every pin path goes through -- manager.Redeem, manager.Request,
// initiate's two paths, and contactinit's two -- so the cap belongs here rather
// than at each of the six call sites.
func TestParsedNameIsCappedAndStripped(t *testing.T) {
	card := func(fn string) string {
		return "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:" + fn +
			"\r\nX-HDTP-VERSION:1\r\nEND:VCARD\r\n"
	}
	parse := func(t *testing.T, fn string) string {
		t.Helper()
		c, err := ParseCard(card(fn))
		if err != nil {
			t.Fatal(err)
		}
		return c.FN
	}

	t.Run("an ordinary name survives untouched", func(t *testing.T) {
		if got := parse(t, "Alice Nakamura"); got != "Alice Nakamura" {
			t.Errorf("a legitimate name was mangled: %q", got)
		}
	})

	t.Run("a name longer than a name is capped", func(t *testing.T) {
		got := parse(t, strings.Repeat("A", 4000))
		if n := len([]rune(got)); n > MaxDisplayName {
			t.Errorf("FN kept %d runes; a peer can blow out every list the "+
				"contact appears in", n)
		}
	})

	t.Run("control characters are removed", func(t *testing.T) {
		got := parse(t, "Alice\x00\x07Nakamura")
		if strings.ContainsAny(got, "\x00\x07") {
			t.Errorf("control characters reached the display name: %q", got)
		}
	})

	t.Run("bidi overrides are removed", func(t *testing.T) {
		// U+202E reverses rendering of everything after it, so "Alice‮krow"
		// paints as "Alicework" -- a name that is not the name that was stored.
		got := parse(t, "Alice\u202ekrow")
		if strings.ContainsRune(got, '\u202e') {
			t.Errorf("a bidi override reached the display name: %q", got)
		}
	})

	t.Run("a name made only of junk becomes empty so the caller falls back", func(t *testing.T) {
		got := parse(t, "\u200f\u202d\u202e")
		if got != "" {
			t.Errorf("FN %q is invisible but non-empty, so the UI shows a blank "+
				"label instead of falling back to the fingerprint", got)
		}
	})
}

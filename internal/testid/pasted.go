package testid

import (
	"slices"
	"strings"
	"testing"
)

// Pasted is a card as a chat delivered the owner's on 2026-10-05: every continuation of X-HDTP-CERT
// without its leading space but the third, a blank line after the first and the fourth, LF line ends.
// hdtp-identity's card_paste tests and hdtp-spec's vectors/check.mjs damage their cards the same way.
func Pasted(t testing.TB, card string) string {
	t.Helper()
	lines := strings.Split(card, "\r\n")
	first := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "X-HDTP-CERT:") })
	if first < 0 {
		t.Fatal("testid.Pasted: the card carries no X-HDTP-CERT")
	}
	conts := 0
	for _, l := range lines[first+1:] {
		if strings.HasPrefix(l, " ") {
			conts++
		}
	}
	if conts < 4 {
		t.Fatalf("testid.Pasted: the certificate is folded over %d lines, too few to damage", conts+1)
	}
	for k := 1; k <= conts; k++ {
		l := lines[first+k]
		if k != 3 {
			l = l[1:]
		}
		if k == 1 || k == 4 {
			l += "\n"
		}
		lines[first+k] = l
	}
	return strings.Join(lines, "\n")
}

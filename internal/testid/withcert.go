package testid

import (
	"strings"
	"testing"
)

// WithoutCert is the card with its X-HDTP-CERT property, and every continuation line of it, removed.
func WithoutCert(t testing.TB, card string) string {
	t.Helper()
	var b strings.Builder
	in := false
	for _, line := range strings.SplitAfter(card, "\r\n") {
		in = strings.HasPrefix(line, "X-HDTP-CERT:") || (in && strings.HasPrefix(line, " "))
		if !in {
			b.WriteString(line)
		}
	}
	out := b.String()
	if out == card || strings.Contains(out, "X-HDTP-CERT") {
		t.Fatal("testid.WithoutCert: the card did not lose its certificate")
	}
	return out
}

// WithCert is the card with its certificate's value replaced by value, on one line.
func WithCert(t testing.TB, card, value string) string {
	t.Helper()
	start, end := strings.Index(card, "X-HDTP-CERT:"), strings.Index(card, "\r\nX-HDTP-SEAL")
	if start < 0 || end < start {
		t.Fatal("testid.WithCert: the card carries no X-HDTP-CERT followed by X-HDTP-SEAL")
	}
	return card[:start] + "X-HDTP-CERT:" + value + card[end:]
}

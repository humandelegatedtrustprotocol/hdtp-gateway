package testid

import (
	"strings"
	"testing"
)

// WithCert is the card with its certificate's value replaced by value, on one line.
func WithCert(t testing.TB, card, value string) string {
	t.Helper()
	start, end := strings.Index(card, "X-HDTP-CERT:"), strings.Index(card, "\r\nX-HDTP-SEAL")
	if start < 0 || end < start {
		t.Fatal("testid.WithCert: the card carries no X-HDTP-CERT followed by X-HDTP-SEAL")
	}
	return card[:start] + "X-HDTP-CERT:" + value + card[end:]
}

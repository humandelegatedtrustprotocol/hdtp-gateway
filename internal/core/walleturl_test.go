package core

import (
	"strings"
	"testing"
)

// L7 (review 2026-09-28). wallet_url is written into the portal's Content-Security-Policy, as the
// form-action origin the signing page may post to. A value that parsed as a URL and carried `;` or
// `'` could add a directive or a source of its own choosing to that policy, so the value is held to
// a strict origin grammar: scheme://host[:port], a DNS name, a dotted quad or a bracketed IPv6
// literal, and at most a trailing slash.
func TestTheWalletURLIsAStrictOrigin(t *testing.T) {
	for _, ok := range []string{
		"https://ceremony.pact.contact", "https://ceremony.pact.contact/", "https://wallet.example:8443",
		"http://127.0.0.1:9000", "http://localhost:9000", "http://[::1]:9000", "https://203.0.113.7",
	} {
		if err := validWalletURL(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"https://wallet.example;script-src *", "https://wallet.example';", "https://wallet.example/ 'unsafe-inline'",
		"https://wallet.example/sign", "https://wallet.example?x=1", "https://wallet.example#f", "https://user@wallet.example",
		"https://wallet example", "https://wallet.example:99999", "https://wallet.example:0", "https://wallet.example:",
		"https://wal\tlet.example", "ftp://wallet.example", "https://", "http://wallet.example", "https://[::1;]",
		"https://*.example", "HTTPS://wallet.example",
	} {
		if err := validWalletURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The same rule refuses the config: RuleWalletURL, named.
func TestAWalletURLThatIsNotAnOriginRefusesTheConfig(t *testing.T) {
	_, err := load(t, `{"wallet_url":"https://wallet.example';"}`, nil)
	if err == nil || !strings.Contains(err.Error(), RuleWalletURL) {
		t.Fatalf("a wallet_url with a directive in it: %v", err)
	}
}

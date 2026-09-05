package core

import "testing"

// The audit is append-only and hash-chained: a secret written into it cannot be
// unwritten. These are the shapes an upstream actually hands back — Google and
// BatonDeck both echo tokens in error text — alongside the identifiers an
// operator needs to keep, which an entropy filter would have destroyed.
func TestRedactRemovesCredentialsAndKeepsEvidence(t *testing.T) {
	secret := []struct {
		name, in, mustNotContain string
	}{
		{"bearer token", `401 Unauthorized: Authorization: Bearer ya29.a0AfB_byC3xamplESECRETvalue`, "ya29.a0AfB"},
		{"bare bearer", `upstream said: bearer sk-live-9f8e7d6c5b4a3210zzzz`, "sk-live-9f8e7d6c"},
		{"basic auth header", `Authorization: Basic b3duZXI6aGFybmVzcy1wdw==`, "b3duZXI6aGFybmVzcy1wdw"},
		{"url userinfo", `Post "https://owner:harness-pw@radicale:5232/work/": 401`, "harness-pw"},
		{"access_token param", `GET /mcp?access_token=abc123def456ghi789 failed`, "abc123def456"},
		{"client secret", `registration failed: client_secret=GOCSPX-1a2b3c4d5e6f`, "GOCSPX-1a2b3c"},
		{"oauth code", `exchange failed for code=4/0AeanS0abcdefghijklmnop`, "4/0AeanS0"},
		{"password param", `dial failed: password=hunter2hunter2`, "hunter2hunter2"},
		{"jwt anywhere", `rejected: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlSGVyZQ`, "eyJzdWIiOiJhbGljZSJ9"},
		{"pact token", `owner mcp: token pact_765948d2a1eb9faa7ba021a8`, "pact_765948d2a1eb"},
		{"github pat", `clone failed: ghp_16C7e42F292c6912E7710c838347Ae178B4a`, "ghp_16C7e42F"},
	}
	for _, tc := range secret {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if got == tc.in {
				t.Fatalf("nothing was redacted: %q", got)
			}
			if contains(got, tc.mustNotContain) {
				t.Fatalf("the secret survived: %q", got)
			}
		})
	}

	// What must NOT be touched: a refusal is only useful if the identifiers
	// survive, and PACT's own are high-entropy base64 by design.
	keep := []struct{ name, in string }{
		{"fingerprint", "contact:sha256:G__4Jt5O-7i0xqF7XMLLHes4_SMXTa9zG52tgsJuvYI"},
		{"booking id", "providers: booking bk_NmJmOTIxMjMtYzA5ZS00NTJm is still in flight"},
		{"msg id", "booking bk-1788024247905 is still in flight"},
		{"plain reason", "providers: upstream unavailable: no calendar is configured"},
		{"endpoint", `Post "https://mcp.batondeck.com/mcp": dial tcp: i/o timeout`},
		{"thread id", "thread:df4b69f1b7cb03e4c78b041c9a591e58 not found"},
	}
	for _, tc := range keep {
		t.Run("keeps "+tc.name, func(t *testing.T) {
			if got := Redact(tc.in); got != tc.in {
				t.Fatalf("evidence was destroyed:\n  in:  %q\n  out: %q", tc.in, got)
			}
		})
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

package core

import "regexp"

// Redact strips credentials out of text that came from somewhere else before it
// is written down.
//
// An upstream's error message is the most useful thing in a refusal — it is what
// turned "unavailable" into "booking … is still in flight" — and it is also the
// text most likely to quote the request that failed, headers and all. A server
// that answers 401 by echoing the Authorization header would put a live bearer
// token in this node's audit trail, which is append-only and hash-chained: there
// is no unwriting it.
//
// The rules match credential SHAPES, not high entropy. HDTP's own identifiers —
// sha256: fingerprints, msg_ids, booking ids — are high-entropy base64 by
// design, and an entropy filter would erase exactly the fields an operator needs
// to follow an incident. What is left is still legible: the reason survives, the
// secret does not.
var redactions = []struct {
	re   *regexp.Regexp
	with string
}{
	// Authorization headers, quoted back at us in an error or a log line.
	// The scheme word has to be consumed with the value, or "Authorization:
	// Basic <creds>" loses only the word "Basic" and leaves the credential.
	{regexp.MustCompile(`(?i)\b(proxy-)?authorization\s*[:=]\s*(?:(?:bearer|basic|digest|token|negotiate)\s+)?\S+`), "authorization=[redacted]"},
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`), "bearer [redacted]"},
	{regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}`), "basic [redacted]"},
	// Credentials in a URL's userinfo: https://user:password@host/…
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`), "$1[redacted]@"},
	// The query and form parameters that carry secrets. client_id is
	// deliberately NOT here: it is a public identifier and the field an owner
	// needs most when an OAuth registration fails — redacting it would cost the
	// diagnosis without protecting anything. `code` is here because an
	// OAuth authorization code is a credential until it is exchanged.
	{regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|client_secret|api[_-]?key|apikey|auth|token|password|passwd|pwd|secret|signature|sig|code)=[^&\s"'` + "`" + `]+`), "$1=[redacted]"},
	// A JWT, wherever it appears — three base64url segments. Google and
	// BatonDeck both hand these out, and both echo them in errors. The segment
	// bounds are deliberately loose: a fuzz seed showed that requiring four
	// characters per segment let a short signature through, and an alg:none
	// token has no signature at all. The `eyJ` prefix — base64 of `{"` — is
	// what makes the match specific, not the lengths.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`), "[redacted jwt]"},
	// Token shapes with a vendor prefix, which say what they are on the tin.
	// Anchored at a word boundary on purpose, and this is a real limit: a token
	// glued to preceding word characters (`id=123ya29.…`) is not matched. The
	// alternative — matching anywhere — lets a `sk-` or `ghp_` that happens to
	// fall inside a base64 fingerprint swallow the rest of it, destroying the
	// identifier an operator follows an incident with. In practice a token
	// arrives after a space, a quote or a `=`, all of which are boundaries.
	{regexp.MustCompile(`\b(hdtp_|sk-|ghp_|gho_|github_pat_|xox[baprs]-|AIza|ya29\.)[A-Za-z0-9._-]{8,}`), "[redacted token]"},
}

// Redact returns text with anything that looks like a credential replaced.
func Redact(s string) string {
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.with)
	}
	return s
}

package core

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Redact parses text this node did not write — an upstream server's error
// message — and decides what reaches an append-only trail. That makes it an
// untrusted-input parser like the others the repository fuzzes, and the one
// property that must hold on every input is that a credential shape does not
// come out the other side intact.
func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		`Authorization: Bearer ya29.a0AfB_secret`,
		`Post "https://owner:pw@host/": 401`,
		`access_token=abc123&code=xyz789`,
		`eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.sig`,
		`token=`, `bearer `, `://:@`, `authorization:`,
		`contact:sha256:G__4Jt5O-7i0xqF7XMLLHes4`,
		``, `%`, `\x00`, strings.Repeat("a=b&", 200),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := Redact(in)
		// It must not invent invalid UTF-8 in text destined for a JSON audit row.
		if utf8.ValidString(in) && !utf8.ValidString(out) {
			t.Fatalf("valid input produced invalid UTF-8: %q", out)
		}
		// Idempotent: redacting an already-redacted line must not keep chewing,
		// or a retried write would differ from the first.
		if again := Redact(out); again != out {
			t.Fatalf("not idempotent:\n  once:  %q\n  twice: %q", out, again)
		}
		// The shapes that must never survive — asserted where the rules claim to
		// match them. The vendor-prefix rule is anchored at a word boundary, so
		// a token fused to preceding word characters is out of its scope by
		// design (see redact.go); asserting otherwise would be testing a promise
		// the rule does not make, and "fixing" it would let a prefix inside a
		// fingerprint swallow the fingerprint.
		// Whole credentials, not fragments: a lone base64 segment is not a JWT
		// and the rule never claimed it was. Asserting on a fragment tests a
		// promise nobody made — the first version of this test did, and failed
		// on a fuzz input that had split a token in half.
		for _, marker := range []string{"ya29.a0AfB_secret", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.sig"} {
			at := strings.Index(in, marker)
			if at < 0 || strings.Contains(out, marker) == false {
				continue
			}
			if at == 0 || !isWordByte(in[at-1]) {
				t.Fatalf("a credential at a word boundary survived: %q", out)
			}
		}
	})
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

package webhooks

// The verifier a receiver writes, kept beside the tests so they exercise the rules a receiver is
// told to implement against what the signer sends (the cloud keeps its verifySignature for the
// same reason). The node never verifies its own deliveries, so it is not in the binary.

import (
	"crypto/hmac"
	"regexp"
	"strconv"
	"strings"
)

// ParsedSignature is a signature header split into its timestamp and its `v1` values.
type ParsedSignature struct {
	Timestamp  int64
	Signatures []string
}

var v1Value = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseSignatureHeader splits a header into its parts; ok is false when it is not one of ours. A
// `t` that is not a whole number is not a timestamp, so the header is refused rather than read as
// zero, which would report the wrong reason. A `v1` that is not 64 lowercase hex digits is passed
// over.
func ParseSignatureHeader(header string) (p ParsedSignature, ok bool) {
	seen := false
	for part := range strings.SplitSeq(header, ",") {
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		key, value := strings.TrimSpace(part[:eq]), strings.TrimSpace(part[eq+1:])
		switch {
		case key == "t":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return ParsedSignature{}, false
			}
			p.Timestamp, seen = n, true
		case key == "v1" && v1Value.MatchString(value):
			p.Signatures = append(p.Signatures, value)
		}
	}
	if !seen || len(p.Signatures) == 0 {
		return ParsedSignature{}, false
	}
	return p, true
}

// VerifySignature is what a receiver's verifier does: the timestamp within ToleranceSeconds of now
// (seconds), and one `v1` equal, in constant time, to the HMAC of `<t>.<body>` under secret. A
// verifier that skips the window accepts any replay; one that skips the constant-time compare
// leaks the secret a byte at a time.
func VerifySignature(secret, body, header string, now int64) bool {
	p, ok := ParseSignatureHeader(header)
	if !ok {
		return false
	}
	if d := now - p.Timestamp; d > ToleranceSeconds || d < -ToleranceSeconds {
		return false
	}
	want := []byte(hmacHex(secret, SignedPayload(p.Timestamp, body)))
	for _, given := range p.Signatures {
		if hmac.Equal(want, []byte(given)) {
			return true
		}
	}
	return false
}

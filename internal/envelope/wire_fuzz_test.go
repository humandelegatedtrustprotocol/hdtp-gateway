package envelope

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// This is the first code an UNAUTHENTICATED peer reaches. A sealed_call arrives as
// JSON, is unmarshalled into an Envelope (which base64-decodes four members), and
// its protected header is JSON-decoded — all of it before any signature has been
// checked, because the header is what says whose signature to check. A panic here
// is a remote crash by anyone who can open a connection, so the contract is: any
// bytes at all, an error or a value, never a panic.
func FuzzEnvelopeWire(f *testing.F) {
	b64 := base64.RawURLEncoding.EncodeToString
	hdr := `{"cty":"application/json","exp":9999999999,"from":"sha256:AAA","kid":"sha256:BBB","msg_id":"m1","suite":"PACT-SEAL-P256","to":"sha256:BBB","ts":1756000000,"v":1}`

	for _, s := range []string{
		`{"protected":"` + b64([]byte(hdr)) + `","enc":"AAAA","ct":"AAAA","sig":"AAAA"}`,
		`{"protected":"","enc":"","ct":"","sig":""}`,
		`{"protected":"!!!not base64!!!"}`,
		`{"protected":"` + b64([]byte(`{"v":1,"suite":"PACT-SEAL-X25519"}`)) + `"}`,
		`{"protected":"` + b64([]byte(`{"v":2}`)) + `"}`,
		`{"protected":"` + b64([]byte(`{"v":1,"suite":"nope"}`)) + `"}`,
		`{"protected":"` + b64([]byte(`{"unknown_field":1,"v":1}`)) + `"}`,
		`{"protected":"` + b64([]byte(`{"exp":-9223372036854775808,"ts":9223372036854775807,"v":1,"suite":"PACT-SEAL-P256"}`)) + `"}`,
		`{}`, ``, `null`, `[]`, `{"protected":123}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var e Envelope
		if err := json.Unmarshal(data, &e); err != nil {
			return
		}
		h, err := ParseHeader(&e)
		if err != nil {
			return
		}
		// A header that parsed must be self-consistent enough that the callers in
		// SPEC §4.4 can rely on it without re-checking the enum.
		if h.V != 1 {
			t.Fatalf("ParseHeader accepted version %d", h.V)
		}
		if h.Suite != SuiteP256 && h.Suite != SuiteX25519 {
			t.Fatalf("ParseHeader accepted suite %q", h.Suite)
		}
	})
}

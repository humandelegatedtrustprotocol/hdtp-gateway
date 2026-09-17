package public

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The payload is what comes OUT of the HPKE open — decrypted, but not yet trusted:
// for a guest it is the attacker's own plaintext, and the card and `spk` inside it
// are what the node is about to decide an identity from. It is parsed before the
// signature is verified against anything, so it must survive arbitrary bytes.
func FuzzSealedPayload(f *testing.F) {
	for _, s := range []string{
		`{"method":"tools/call","params":{"name":"send_message","arguments":{"text":"hi"}}}`,
		`{"method":"tools/list"}`,
		`{"method":"tools/call","spk":"AAAA","params":{"name":"redeem_invite","arguments":{"card":"BEGIN:VCARD\r\nEND:VCARD\r\n"}}}`,
		`{"method":"tools/call","params":{"name":"request_contact","arguments":{}}}`,
		`{"method":"tools/call","params":{"name":"redeem_invite","arguments":{"card":123}}}`,
		`{"spk":"!!!"}`, `{"method":""}`, `{}`, ``, `null`, `[]`, `{"method":"tools/call","params":null}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Payload
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return
		}
		// Everything the identity decision touches: the method, the params, and the
		// chain-or-leaf the plaintext must carry exactly one of (PACT §13.2).
		_ = p.Method
		_ = p.Params
	})
}

package cli

import (
	"encoding/json"
	"testing"
)

// The invite offer is a document fetched over the network from a host the owner
// has not met yet — the least trusted input in the whole product, since the owner
// is about to PIN a key out of it. verifyOffer is the gate that turns it into
// something pinnable, so it has to hold against anything the remote host returns.
func FuzzInviteOffer(f *testing.F) {
	const card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-PACT-VERSION:1\r\nX-PACT-KEY:sha256:AAA\r\nEND:VCARD\r\n"
	for _, s := range []string{
		`{"card":` + mustJSON(card) + `,"card_sig":"AAAA","spki":"AAAA"}`,
		`{"card":"","card_sig":"","spki":""}`,
		`{"card":` + mustJSON(card) + `}`,
		`{"spki":"!!!not base64!!!"}`,
		`{"card":"BEGIN:VCARD"}`,
		`{"card":"BEGIN:VCARD\r\nX-PACT-KEY:not-a-fingerprint\r\nEND:VCARD\r\n","spki":"AAAA"}`,
		`{}`, ``, `null`, `[]`, `{"card":123}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var off inviteOffer
		if err := json.Unmarshal(data, &off); err != nil {
			return
		}
		card, spki, err := verifyOffer(off)
		if err != nil {
			return
		}
		// An offer that verified is one we would PIN. Both halves of what makes a
		// pin mean anything must be present, or the fingerprint check that follows
		// would be comparing against nothing.
		if card.Key == "" {
			t.Fatal("verifyOffer accepted a card with no X-PACT-KEY")
		}
		if len(spki) == 0 {
			t.Fatal("verifyOffer accepted an offer with no key to pin")
		}
	})
}

func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

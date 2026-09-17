package cli

import (
	"encoding/json"
	"testing"
)

// The invite offer is a document fetched over the network from a host the owner has not met yet —
// the least trusted input in the whole product, since the owner is about to PIN an identity out of
// it. verifyOffer is the gate that turns it into something pinnable, so it has to hold against
// anything the remote host returns.
//
// **The seeds are 2.0 documents now, and one of them is REAL** (2026-09-18). They were all 1.x
// cards, which `verifyOffer` refuses on the first check, so every mutation the fuzzer made was
// explored against an offer that could never be accepted — and a fuzz target that asserts
// properties of ACCEPTED offers learns nothing from a corpus where none are. The valid offer below
// is built the way `offer_test.go` builds it, so mutations start from something that verifies.
func FuzzInviteOffer(f *testing.F) {
	const oneX = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-PACT-VERSION:1\r\nX-PACT-KEY:sha256:AAA\r\nEND:VCARD\r\n"
	p := newTestPeer(f, "Fuzz Peer", "https://agent.fuzz.example/mcp")
	valid, err := json.Marshal(offerFor(f, p, "Fuzz Peer"))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		string(valid),
		`{"card":` + mustJSON(oneX) + `,"card_sig":"AAAA","spki":"AAAA"}`,
		`{"card":"","card_sig":"","spki":"","chain":[]}`,
		`{"card":` + mustJSON(oneX) + `}`,
		`{"spki":"!!!not base64!!!"}`,
		`{"card":"BEGIN:VCARD"}`,
		`{"card":"BEGIN:VCARD\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:not-base64\r\nEND:VCARD\r\n","spki":"AAAA","chain":["a","b"]}`,
		`{"chain":["","",""]}`,
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
		// An offer that verified is one we would PIN. Every part of what makes that pin mean
		// something must be there, or a check further on is comparing against nothing.
		if card.Key == "" {
			t.Fatal("verifyOffer accepted a card that names no root")
		}
		if card.Endpoint == "" {
			t.Fatal("verifyOffer accepted a card with no address to call")
		}
		if len(card.Cert) == 0 {
			t.Fatal("verifyOffer accepted a card with no certificate")
		}
		if len(spki) == 0 {
			t.Fatal("verifyOffer accepted an offer with no key to seal to")
		}
		if len(off.Chain) != 2 {
			t.Fatal("verifyOffer accepted an offer with no [leaf, root] chain")
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

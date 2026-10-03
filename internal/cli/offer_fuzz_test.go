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
// **One of the seeds is REAL** (2026-09-18). They were all cards with no certificate,
// which `verifyOffer` refuses on the first check, so every mutation the fuzzer made was
// explored against an offer that could never be accepted — and a fuzz target that asserts
// properties of ACCEPTED offers learns nothing from a corpus where none are. The valid offer below
// is built the way `offer_test.go` builds it, so mutations start from something that verifies.
func FuzzInviteOffer(f *testing.F) {
	const noCert = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nX-HDTP-VERSION:1\r\nEND:VCARD\r\n"
	p := newTestPeer(f, "Fuzz Peer", "https://agent.fuzz.example/mcp")
	valid, err := json.Marshal(offerFor(f, p, "Fuzz Peer"))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		string(valid),
		`{"card":` + mustJSON(noCert) + `,"card_sig":"AAAA","spki":"AAAA"}`,
		`{"card":"","card_sig":"","spki":"","chain":[]}`,
		`{"card":` + mustJSON(noCert) + `}`,
		`{"spki":"!!!not base64!!!"}`,
		`{"card":"BEGIN:VCARD"}`,
		`{"card":"BEGIN:VCARD\r\nX-HDTP-VERSION:2\r\nEND:VCARD\r\n"}`, // a version this node does not speak
		`{"card":"BEGIN:VCARD\r\nX-HDTP-VERSION:1\r\nX-HDTP-CERT:not-base64\r\nEND:VCARD\r\n","spki":"AAAA","chain":["a","b"]}`,
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
		card, spki, rootCert, err := verifyOffer(off)
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
		// The root's certificate comes back because the pin keeps it: an offer that
		// verified without one would pin a root this host could never prove again.
		if len(rootCert) == 0 {
			t.Fatal("verifyOffer accepted an offer and returned no root certificate")
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

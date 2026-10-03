package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// What an invite offer is, and what it takes to be one worth pinning (SPEC §9.2, §14.2).
//
// There was no positive test for `verifyOffer` at all — only a fuzz target, which asserts
// properties of offers that VERIFY and is therefore silent when nothing verifies. That is how the
// 2.0 break went unnoticed: `verifyOffer` required the card to carry `X-PACT-KEY`, which no 2.0
// card does, so `hdtp-gateway contact init <invite-url>` refused every real invite and the suite
// stayed green. A positive case is what makes the negatives below mean anything.

// offerFor builds the document a 2.0 node's landing page serves: the card, the `[leaf, root]`
// chain that proves it, the leaf's key, and the leaf key's signature over the card bytes.
func offerFor(t testing.TB, p *testPeer, fn string) inviteOffer {
	t.Helper()
	card := p.Card(fn)
	sig, err := hdtpidentity.SignDetached(p.Host.Key, []byte(card))
	if err != nil {
		t.Fatal(err)
	}
	return inviteOffer{
		Card:    card,
		CardSig: base64.RawURLEncoding.EncodeToString(sig),
		Chain:   []string{hdtpidentity.B64url(p.Host.LeafDER), hdtpidentity.B64url(p.Wallet.RootDER)},
	}
}

func TestVerifyOfferAcceptsARealTwoZeroInvite(t *testing.T) {
	p := newTestPeer(t, "Alina Rao", "https://agent.alina.example/mcp")
	card, spki, rootCert, err := verifyOffer(offerFor(t, p, "Alina Rao"))
	if err != nil {
		t.Fatalf("a real 2.0 offer was refused: %v", err)
	}
	// What the pin is made of: the ROOT is the identity, the address comes from the leaf's own
	// subjectAltName rather than from a property anybody could write, and the key is the leaf's.
	if card.Key != p.Root() {
		t.Errorf("pinned %s, want the root %s", card.Key, p.Root())
	}
	if card.Endpoint != p.Endpoint {
		t.Errorf("the address is %q, want the leaf's %q", card.Endpoint, p.Endpoint)
	}
	if base64.RawURLEncoding.EncodeToString(spki) != base64.RawURLEncoding.EncodeToString(p.Host.Key.Public().SPKI) {
		t.Error("the key returned is not the leaf's")
	}
	// The ROOT's own certificate comes back too, because the pin keeps it (migration
	// 0029): the offer's chain is the one moment this host holds it, and a sealed call
	// afterwards carries the chain inside its ciphertext where only Decide sees it.
	if len(rootCert) == 0 {
		t.Error("the offer verified and returned no root certificate to pin")
	}
	// And the peer that describes: called at that address, pinned by that root, sealed to that
	// leaf. `Protocol: 2` is what `outbound.Client` requires before it will speak at all.
	peer := peerOfCard(card)
	if !peer.Known() || peer.Root != p.Root() || peer.Endpoint != p.Endpoint || len(peer.Leaf) == 0 {
		t.Errorf("the peer built from the card is %+v", peer)
	}
}

// HDTP §4 defines an invite landing's machine view as exactly three members:
// `{"card","card_sig","chain"}`. This redeemer also demanded a fourth, `spki`, and refused the
// invite without it — "the invite carried no usable public key" — and then required that key to
// equal the one in the chain's leaf, which it had validated a few lines earlier and already held.
// So the member was pure redundancy, and the demand for it meant this node could not redeem an
// invite from any implementation that follows §4 to the letter. It interoperated with the cloud
// only because the cloud carries the same leftover: `spki` is the first generation's "SPKI distribution",
// from when a card carried a key's HASH and the key had to travel beside it. A 2.0 card carries
// the leaf certificate, and the key is in it.
func TestVerifyOfferNeedsOnlyWhatTheSpecSaysALandingCarries(t *testing.T) {
	p := newTestPeer(t, "Alina Rao", "https://alina.example/mcp")
	off := offerFor(t, p, "Alina Rao")

	// Exactly what §4 says travels: marshal the offer and keep only the three spec members.
	raw, err := json.Marshal(off)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for k := range wire {
		if k != "card" && k != "card_sig" && k != "chain" {
			delete(wire, k)
		}
	}
	exact, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var specOffer inviteOffer
	if err := json.Unmarshal(exact, &specOffer); err != nil {
		t.Fatal(err)
	}

	card, spki, rootCert, err := verifyOffer(specOffer)
	if err != nil {
		t.Fatalf("a landing carrying exactly {card, card_sig, chain} was refused: %v", err)
	}
	if card.Key != p.Root() {
		t.Fatalf("the offer names root %s, want %s", card.Key, p.Root())
	}
	if !bytes.Equal(spki, p.Host.Key.Public().SPKI) {
		t.Fatal("the key to seal to must be the validated leaf's own, since nothing else carries it")
	}
	if !bytes.Equal(rootCert, p.Wallet.RootDER) {
		t.Fatal("the root certificate must come from the validated chain")
	}
}

func TestVerifyOfferRefusals(t *testing.T) {
	p := newTestPeer(t, "Alina Rao", "https://agent.alina.example/mcp")
	other := newTestPeer(t, "Someone Else", "https://agent.alina.example/mcp")

	for _, tc := range []struct {
		name string
		why  string
		mut  func(*inviteOffer)
	}{
		{"no chain", "there is no root to pin without one", func(o *inviteOffer) { o.Chain = nil }},
		{"a chain of one", "a chain is exactly [leaf, root]", func(o *inviteOffer) { o.Chain = o.Chain[:1] }},
		{
			"a chain whose leaf is not the card's certificate",
			"the card and the chain would be two peers' documents assembled into a plausible pair",
			func(o *inviteOffer) { o.Chain[0] = hdtpidentity.B64url(other.Host.LeafDER) },
		},
		{
			"a root that did not sign the leaf",
			"the root is the identity: accepting an unrelated one pins the wrong person",
			func(o *inviteOffer) { o.Chain[1] = hdtpidentity.B64url(other.Wallet.RootDER) },
		},
		{
			"a chain with a character outside base64url",
			"it is refused as the identity core refuses it, never skipped (the identity core 0.4.2's DecodeB64url)",
			func(o *inviteOffer) { o.Chain[0] = "!" + o.Chain[0] },
		},
		// "a key that is not the leaf's" was a case here: the offer carried the key a second time
		// as `spki`, and swapping it was refused. There is no second key now — the one sealed to is
		// read from the validated leaf — so the swap cannot be attempted rather than being caught.
		{"no signature", "SPEC §9.2 serves a SIGNED card", func(o *inviteOffer) { o.CardSig = "" }},
		{
			"a signature over something else",
			"the card and the key must be proven to belong together",
			func(o *inviteOffer) {
				sig, err := hdtpidentity.SignDetached(other.Host.Key, []byte(p.Card("Alina Rao")))
				if err != nil {
					t.Fatal(err)
				}
				o.CardSig = base64.RawURLEncoding.EncodeToString(sig)
			},
		},
		{"a 1.x card", "the generation is gone; its card names a bare key", func(o *inviteOffer) {
			o.Card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Old\r\nX-PACT-VERSION:1\r\n" +
				"X-PACT-ENDPOINT:https://old.example/mcp\r\nX-PACT-KEY:sha256:AAA\r\nEND:VCARD\r\n"
		}},
	} {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			off := offerFor(t, p, "Alina Rao")
			tc.mut(&off)
			if _, _, _, err := verifyOffer(off); err == nil {
				t.Errorf("accepted an offer with %s — %s", tc.name, tc.why)
			}
		})
	}
}

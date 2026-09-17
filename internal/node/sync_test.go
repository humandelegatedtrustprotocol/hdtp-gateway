package node

import (
	"encoding/base64"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/testid"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// The sync sweep's whole trust decision: a re-fetched card is applied only
// when it still names the pinned key AND its signature verifies under it.
// Sync must never be a way to move a pin — that is update_contact's job, with
// its old-key signature.
// verifySyncedCard is the whole trust decision of the periodic sync: a re-fetched
// card must still name the pinned ROOT, and its signature must verify under the key
// this node holds for that contact.
//
// It used to be checked against 1.x cards, where the card's X-PACT-KEY and the
// pinned key were one value. They are two now — the pin is the root, the signing
// key is the leaf's — and a card that confuses them is exactly what a compromised
// endpoint would send.
func TestVerifySyncedCard(t *testing.T) {
	w := testid.NewWallet(t, "Peer")
	h := w.Issue(t, "https://p.example/mcp")
	card := h.Card("Peer", "required")
	sign := func(text string) string {
		sig, err := pactidentity.SignDetached(h.Key, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, card, sign(card)); err != nil {
		t.Fatalf("a valid card was refused: %v", err)
	}

	// A card from a DIFFERENT root is refused even with a valid signature by the
	// pinned key — the exact move a compromised endpoint would try.
	other := testid.NewWallet(t, "Peer")
	swapped := other.Issue(t, "https://p.example/mcp").Card("Peer", "required")
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, swapped, sign(swapped)); err == nil {
		t.Fatal("a root swap slid through sync")
	}

	// A tampered card fails the signature.
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, card+"X", sign(card)); err == nil {
		t.Fatal("a tampered card verified")
	}

	// A signature by anyone but the pinned key fails.
	foreign, err := pactidentity.SignDetached(other.Key, []byte(card))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, card, base64.RawURLEncoding.EncodeToString(foreign)); err == nil {
		t.Fatal("a foreign signature verified")
	}

	// Intake rules still apply: a card with no certificate at all is refused.
	bare := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Peer\r\nX-PACT-VERSION:2\r\nEND:VCARD\r\n"
	if err := verifySyncedCard(w.Fpr, h.Key.Public.SPKI, bare, sign(bare)); err == nil {
		t.Fatal("a card with no certificate was accepted")
	}
}

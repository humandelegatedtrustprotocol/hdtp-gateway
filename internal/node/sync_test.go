package node

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// The sync sweep's whole trust decision: a re-fetched card is applied only
// when it still names the pinned key AND its signature verifies under it.
// Sync must never be a way to move a pin — that is update_contact's job, with
// its old-key signature.
func TestVerifySyncedCard(t *testing.T) {
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	card, err := contacts.BuildCard(contacts.Card{FN: "Peer", Endpoint: "https://p.example/mcp", Key: kp.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(text string) string {
		sig, err := identity.SignBytes(kp, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sig)
	}

	if err := verifySyncedCard(kp.Fingerprint, spki, card, sign(card)); err != nil {
		t.Fatalf("a valid card was refused: %v", err)
	}

	// A card naming a DIFFERENT key is refused even with a valid signature by
	// the pinned key — the exact move a compromised endpoint would try.
	other, _ := identity.Generate(identity.AlgoP256)
	swapped, _ := contacts.BuildCard(contacts.Card{FN: "Peer", Endpoint: "https://p.example/mcp", Key: other.Fingerprint})
	if err := verifySyncedCard(kp.Fingerprint, spki, swapped, sign(swapped)); err == nil {
		t.Fatal("a key swap slid through sync")
	}

	// A tampered card fails the signature.
	tampered := card + "X"
	if err := verifySyncedCard(kp.Fingerprint, spki, tampered, sign(card)); err == nil {
		t.Fatal("a tampered card verified")
	}

	// A signature by anyone but the pinned key fails.
	otherSig, _ := identity.SignBytes(other, []byte(card))
	if err := verifySyncedCard(kp.Fingerprint, spki, card, base64.RawURLEncoding.EncodeToString(otherSig)); err == nil {
		t.Fatal("a foreign signature verified")
	}

	// Intake rules still apply: an endpoint-and-gateway-less card is refused.
	bare, _ := contacts.BuildCard(contacts.Card{FN: "Peer", Key: kp.Fingerprint})
	if err := verifySyncedCard(kp.Fingerprint, spki, bare, sign(bare)); err == nil {
		t.Fatal("an unreachable card was accepted")
	}
}

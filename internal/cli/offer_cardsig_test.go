package cli

import (
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// HDTP §3, §13.1: an invite's `card_sig` is read as a refreshed card's is (internal/node
// TestARefreshedCardSigIsReadStrictly): unpadded base64url and nothing else, verified as the identity
// core verifies. Each refused spelling is refused at the invite door; the honest one gets through.
func TestAnInvitesCardSigIsReadStrictly(t *testing.T) {
	w := testid.NewWallet(t, "Issuer")
	cs := testid.SignedCardSigs(t, w, "https://issuer.example/a/i/mcp", "Issuer")
	chain := []string{hdtpidentity.B64url(cs.Host.Chain[0]), hdtpidentity.B64url(cs.Host.Chain[1])}
	if _, _, _, err := verifyOffer(inviteOffer{Card: cs.Card, CardSig: cs.Honest, Chain: chain}); err != nil {
		t.Fatalf("the control, the honest signature, was refused: %v", err)
	}
	for name, sig := range cs.Refused {
		if _, _, _, err := verifyOffer(inviteOffer{Card: cs.Card, CardSig: sig, Chain: chain}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

package node

import (
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// HDTP §3: `card_sig` is unpadded base64url, and a reader takes no other spelling of it (as §13.1
// says of an envelope's members); the signature is checked as the identity core checks one, which
// refuses an Ed25519 R of small order (the Rust core's verify_strict). A refreshed `get_card`
// decoded with the non-strict reader, which took spare low bits, and verified with crypto/ed25519,
// which takes a small-order R. Each refused spelling is refused here; the honest one gets through.
func TestARefreshedCardSigIsReadStrictly(t *testing.T) {
	w := testid.NewWallet(t, "Peer")
	cs := testid.SignedCardSigs(t, w, "https://p.example/mcp", "Peer")
	pin := store.Contact{Fingerprint: w.Fpr, Endpoint: cs.Host.Endpoint, Leaf: cs.Host.LeafDER}
	now := time.Now()
	if _, err := verifyRefreshedCard(pin, cs.Host.Chain, cs.Card, cs.Honest, now); err != nil {
		t.Fatalf("the control, the honest signature, was refused: %v", err)
	}
	for name, sig := range cs.Refused {
		if _, err := verifyRefreshedCard(pin, cs.Host.Chain, cs.Card, sig, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

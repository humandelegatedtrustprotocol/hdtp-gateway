package node

import (
	"encoding/base64"
	"regexp"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// A refresh whose chain fails a rule says which rule and nothing of the identity core's reason:
// refresh_contact sends the sentence to the owner as its `why`. It carried the core's reason. The
// control, the chain that proves the leaf, verifies.
func TestARefreshRefusesAChainInTheNodesWords(t *testing.T) {
	w := testid.NewWallet(t, "Peer")
	h := w.Issue(t, "https://p.example/mcp")
	other := testid.NewWallet(t, "Peer")
	card := h.Card("Peer", "required")
	sig, err := hdtpidentity.SignDetached(h.Key, []byte(card))
	if err != nil {
		t.Fatal(err)
	}
	cardSig := base64.RawURLEncoding.EncodeToString(sig)
	pin := store.Contact{Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI, Endpoint: h.Endpoint, Leaf: h.LeafDER}
	if _, err := verifyRefreshedCard(pin, h.Chain, card, cardSig, time.Now()); err != nil {
		t.Fatalf("the control: %v", err)
	}
	_, err = verifyRefreshedCard(pin, [][]byte{h.LeafDER, other.RootDER}, card, cardSig, time.Now())
	if err == nil || !regexp.MustCompile(`^the chain it answered with fails rule \d+$`).MatchString(err.Error()) {
		t.Errorf("a leaf under another root: %v, want the rule alone", err)
	}
}

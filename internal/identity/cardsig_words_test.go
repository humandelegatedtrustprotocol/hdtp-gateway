package identity

import (
	"testing"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// A card signature checked under a key that does not read is refused in a fixed sentence, without
// the parser's text. The control, a key that reads, gets as far as the signature.
func TestVerifyCardSigRefusesAnUnreadableKeyInTheNodesWords(t *testing.T) {
	const sig = "AAAA"
	if err := VerifyCardSig([]byte{0x30, 0x01}, "card", sig); err == nil || err.Error() != "the key to check the card under is unreadable" {
		t.Errorf("an unreadable key: %v", err)
	}
	k, err := hdtpidentity.GenerateKey("p256")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCardSig(k.Public().SPKI, "card", sig); err == nil || err.Error() != "the card signature does not verify" {
		t.Errorf("the control: %v", err)
	}
}

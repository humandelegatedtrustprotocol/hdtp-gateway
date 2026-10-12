package contacts

import (
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// ValidateInbound refuses a card in the node's words: a certificate that does not read is "the
// card's certificate does not parse", any other refusal of it "the card's certificate is not one
// this node accepts", and neither carries the core's reason (an x509 parser's text among it). It
// wrapped the core's error, whose text reached add_contact's bad_request. The control, a card that
// reads, is read.
func TestIntakeRefusesACardInTheNodesWords(t *testing.T) {
	card, _, h := testid.Card(t, "Chitra Iyer", "https://chitra.example/mcp", "optional")
	if _, err := ValidateInbound(card); err != nil {
		t.Fatalf("the control: %v", err)
	}
	b64 := hdtpidentity.B64url(h.LeafDER)
	for _, c := range []struct {
		what, text, want string
		unreadable       bool
	}{
		{"a cut certificate", testid.WithCert(t, card, b64[:120]), "the card's certificate does not parse", true},
		{"two certificates", strings.Replace(card, "END:VCARD", "X-HDTP-CERT:"+b64+"\r\nEND:VCARD", 1), "the card's certificate is not one this node accepts", false},
	} {
		_, err := ValidateInbound(c.text)
		if err == nil || err.Error() != c.want || CertificateUnreadable(err) != c.unreadable {
			t.Errorf("%s: %v (unreadable %v), want %q (unreadable %v)", c.what, err, CertificateUnreadable(err), c.want, c.unreadable)
		}
		// Wrapped as the manager wraps it, the words and the reading survive.
		var m Manager
		if werr := m.InitiatedByFingerprint(t.Context(), "acct", "sha256:x", c.text); werr == nil ||
			!strings.HasSuffix(werr.Error(), c.want) || CertificateUnreadable(werr) != c.unreadable {
			t.Errorf("%s through the manager: %v", c.what, werr)
		}
	}
}

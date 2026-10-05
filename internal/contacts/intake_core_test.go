package contacts

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Intake reads a card once, by the identity core: the name, the seal, the root, the endpoint and
// the certificate are the core's, folded or not. A certificate that does not read is told apart for
// the person who pasted it (CertificateUnreadable); a refusal for anything else is not that one.
func TestIntakeReadsACardByTheCoreAlone(t *testing.T) {
	card, w, h := testid.Card(t, "Chitra Iyer", "https://chitra.example/mcp", "optional")
	for _, tc := range []struct{ what, text string }{
		{"folded", card},
		{"not folded at all", strings.ReplaceAll(card, "\r\n ", "")},
	} {
		c, err := ValidateInbound(tc.text)
		if err != nil {
			t.Errorf("a card %s: %v", tc.what, err)
			continue
		}
		if c.Key != w.Fpr || c.Endpoint != h.Endpoint || c.FN != "Chitra Iyer" || c.Seal != "optional" || c.Version != cardMajor || !bytes.Equal(c.Cert, h.LeafDER) {
			t.Errorf("a card %s: %+v", tc.what, c)
		}
		if got := CardName(tc.text); got != "Chitra Iyer" {
			t.Errorf("a card %s is named %q", tc.what, got)
		}
		if seal, err := SealOf(tc.text, time.Now()); err != nil || seal != "optional" {
			t.Errorf("a card %s: its seal on file reads as %q, %v", tc.what, seal, err)
		}
	}

	b64 := hdtpidentity.B64url(h.LeafDER)
	// Cut at 120 characters, a multiple of four: the base64url reads, the DER does not.
	_, err := ValidateInbound(testid.WithCert(t, card, b64[:120]))
	if err == nil || !CertificateUnreadable(err) || !strings.Contains(err.Error(), "the card's certificate") {
		t.Errorf("a cut certificate: %v, unreadable %v", err, CertificateUnreadable(err))
	}
	// A refusal for anything else is not that one: another version, no certificate at all (a phone's
	// export), or two of them — the last two refused by the core, as CardErrors, for what a file or a
	// link would not fix.
	for _, tc := range []struct{ what, text string }{
		{"a card of another version", strings.Replace(card, "X-HDTP-VERSION:1", "X-HDTP-VERSION:2", 1)},
		{"a card with no certificate", testid.WithoutCert(t, card)},
		{"a card with two certificates", strings.Replace(card, "END:VCARD", "X-HDTP-CERT:"+b64+"\r\nEND:VCARD", 1)},
	} {
		if _, err := ValidateInbound(tc.text); err == nil || CertificateUnreadable(err) {
			t.Errorf("%s is not a certificate that does not read: %v", tc.what, err)
		}
	}
	// One character of the signature changed: intake reads another leaf, as it reads any card altered
	// in transit; reading cannot find it, a card carrying no root (hdtp-identity's card_paste tests show
	// the leaf does not validate under its root).
	mid := len(b64) - 30
	swap := "A"
	if b64[mid] == 'A' {
		swap = "B"
	}
	c, err := ValidateInbound(testid.WithCert(t, card, b64[:mid]+swap+b64[mid+1:]))
	if err != nil || bytes.Equal(c.Cert, h.LeafDER) {
		t.Errorf("a changed character: %v; want another leaf, read", err)
	}
}

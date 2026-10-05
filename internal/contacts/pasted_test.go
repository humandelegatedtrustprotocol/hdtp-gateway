package contacts

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// HDTP §3, Reading a card: a card whose folding a paste damaged is read by intake, its name and its
// seal included, because intake reads a card once, by the identity core. ParseCard read it first
// here and refused it: go-vcard drops a continuation that lost its space, a line with no colon, and
// the certificate left was `not base64url`.
func TestAPastedCardIsReadByTheCore(t *testing.T) {
	card, w, h := testid.Card(t, "Chitra Iyer", "https://chitra.example/mcp", "optional")
	pasted := testid.Pasted(t, card)
	if pasted == card || strings.Contains(pasted, "\r\n ") {
		t.Fatal("the pasted card is not damaged")
	}
	c, err := ValidateInbound(pasted)
	if err != nil {
		t.Fatalf("a pasted card: %v", err)
	}
	if c.Key != w.Fpr || c.Endpoint != h.Endpoint || c.FN != "Chitra Iyer" || c.Seal != "optional" || !bytes.Equal(c.Cert, h.LeafDER) {
		t.Errorf("a pasted card: %+v", c)
	}
	if got := CardName(pasted); got != "Chitra Iyer" {
		t.Errorf("a pasted card is named %q", got)
	}
	if seal, err := SealOf(pasted, time.Now()); err != nil || seal != "optional" {
		t.Errorf("a pasted card's seal on file reads as %q, %v", seal, err)
	}
	// A seal after the pasted certificate is a property, not more certificate.
	if c, err := ValidateInbound(strings.Replace(pasted, "X-HDTP-SEAL:optional", "X-HDTP-SEAL:required", 1)); err != nil || c.Seal != "required" {
		t.Errorf("the seal after a pasted certificate: %+v %v", c, err)
	}
}

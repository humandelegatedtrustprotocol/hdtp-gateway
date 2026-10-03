package contacts

import (
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	"os"
	"strings"
	"testing"
)

// A card is built by hdtp-identity from a certificate: it writes the three properties HDTP §3
// gives a card and no other. What is worth proving is that the parser reads a real card and
// recovers the root and the endpoint from INSIDE the certificate rather than from any property.
func TestACardCarriesItsIdentityInTheCertificate(t *testing.T) {
	card, w, h := testid.Card(t, "Sumit Agrawal", "https://hdtp.sumit.example/mcp", "required")
	for _, want := range []string{"BEGIN:VCARD", "X-HDTP-VERSION:1", "X-HDTP-CERT:", "X-HDTP-SEAL:required", "FN:Sumit Agrawal"} {
		if !strings.Contains(card, want) {
			t.Fatalf("built card missing %q:\n%s", want, card)
		}
	}
	for _, line := range strings.Split(card, "\r\n") {
		name, _, _ := strings.Cut(line, ":")
		if strings.HasPrefix(name, "X-HDTP-") && name != "X-HDTP-VERSION" && name != "X-HDTP-CERT" && name != "X-HDTP-SEAL" {
			t.Errorf("a card carries %q, which is not a property a card has", name)
		}
	}
	out, err := ValidateInbound(card)
	if err != nil {
		t.Fatal(err)
	}
	if out.FN != "Sumit Agrawal" || out.Seal != "required" {
		t.Errorf("card fields lost: %+v", out)
	}
	if out.Key != w.Fpr {
		t.Errorf("Key = %q, want the ROOT fingerprint %q", out.Key, w.Fpr)
	}
	if out.Endpoint != h.Endpoint {
		t.Errorf("Endpoint = %q, want the leaf's SAN %q", out.Endpoint, h.Endpoint)
	}
}

// The fixture is a phone's contacts-app export of a card: vCard 3.0, the phone's own grouped
// properties, and a long X- value the phone folded onto a second line. It is kept because the
// FOLDING is what it proves — a phone wraps long property values and the parser has to unfold
// them, which is what happens to X-HDTP-CERT. The card in it carries no certificate, so it
// names nobody and intake refuses it for that.
func TestPhoneExportedFixtureUnfoldsButDoesNotImport(t *testing.T) {
	raw, err := os.ReadFile("testdata/iphone-export.vcf")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCard(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.FN != "Alina Rao" {
		t.Fatalf("FN = %q", c.FN)
	}
	if c.Seal != "required" {
		t.Fatalf("a folded X- property was lost: %+v", c)
	}
	if _, err := ValidateInbound(string(raw)); err == nil || !strings.Contains(err.Error(), "the card's certificate") {
		t.Errorf("a phone export with no certificate must be refused at intake for that: %v", err)
	}
}

func TestForeignCardTolerated(t *testing.T) {
	plain := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:No HDTP\r\nEND:VCARD\r\n"
	c, err := ParseCard(plain)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "" && c.Key != "" {
		t.Fatal("foreign card claimed as HDTP")
	}
	if c.FN != "No HDTP" {
		t.Fatalf("FN = %q", c.FN)
	}
}

func TestCardHelpersUseParser(t *testing.T) {
	card, _, _ := testid.Card(t, "Alina Rao", "https://alina.example/mcp", "required")
	if CardName(card) != "Alina Rao" {
		t.Fatal("CardName no longer extracts from real cards")
	}
	// The phone fixture carries a name a phone can read and no certificate.
	// CardName still works on it; intake refuses it.
	raw, _ := os.ReadFile("testdata/iphone-export.vcf")
	if CardName(string(raw)) != "Alina Rao" {
		t.Fatal("CardName no longer reads a card exported from a phone")
	}
	if _, err := ValidateInbound(string(raw)); err == nil {
		t.Fatal("a card with no certificate still yields an identity")
	}
}

func FuzzVCardParse(f *testing.F) {
	seeds := []string{
		"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\nVERSION:3.0\nFN:Y\nX-HDTP-FUTURE:sha256:abc\nEND:VCARD\n",
		"", "BEGIN:VCARD", "FN:loose\r\n", "BEGIN:VCARD\r\nVERSION:4.0\r\nX-HDTP-FUTURE:https://e\r\n x\r\nEND:VCARD\r\n",
	}
	if raw, err := os.ReadFile("testdata/iphone-export.vcf"); err == nil {
		seeds = append(seeds, string(raw))
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Must never panic; errors are fine. Length-cap first like the boundary does.
		if len(input) > 64*1024 {
			input = input[:64*1024]
		}
		c, err := ParseCard(input)
		if err == nil {
			_ = c.Key
			_, _ = ValidateInbound(input)
		}
	})
}

// HDTP §3 intake: the certificate IS the card. Strict where identity or
// reachability is at stake, tolerant of properties it does not know.
//
// Every refused card but the last is the good card with ONE thing changed, and the refusal must
// say that thing: a card refused for another reason than its case names proves nothing about
// the rule the case is there for.
func TestValidateInbound(t *testing.T) {
	good, _, _ := testid.Card(t, "P", "https://p.example/mcp", "required")
	const versionLine = "X-HDTP-VERSION:1\r\n"
	version := func(line string) string { return strings.Replace(good, versionLine, line, 1) }
	// The certificate is a long value, so the card folds it: the property is its line and every
	// continuation line after it (one that begins with a space).
	var noCert strings.Builder
	inCert := false
	for _, line := range strings.SplitAfter(good, "\r\n") {
		inCert = strings.HasPrefix(line, "X-HDTP-CERT:") || (inCert && strings.HasPrefix(line, " "))
		if !inCert {
			noCert.WriteString(line)
		}
	}
	if strings.Contains(noCert.String(), "X-HDTP-CERT") || !strings.Contains(noCert.String(), versionLine+"X-HDTP-SEAL:") {
		t.Fatalf("the card without its certificate is not the good card less one property:\n%s", noCert.String())
	}
	for _, tc := range []struct {
		name, card string
		refused    string // what the refusal says; empty for a card that is taken
	}{
		{"a card", good, ""},
		{"a card with an X- property it does not know", strings.Replace(good, "FN:P", "FN:P\r\nX-HDTP-FUTURE:whatever", 1), ""},
		{"another major version", version("X-HDTP-VERSION:2\r\n"), `names protocol version "2"`},
		{"a later major version", version("X-HDTP-VERSION:3\r\n"), `names protocol version "3"`},
		{"a minor version: the property is the major and nothing else", version("X-HDTP-VERSION:1.3\r\n"), `names protocol version "1.3"`},
		{"no version at all", version(""), "carries no X-HDTP-VERSION"},
		{"the right version and no certificate", noCert.String(), "the card's certificate"},
		{"not a vcard at all", "hello", "vcard"},
	} {
		if tc.refused != "" && tc.card == good {
			t.Fatalf("%s: the case changed nothing in the good card", tc.name)
		}
		_, err := ValidateInbound(tc.card)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.refused != "" && err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.refused != "" && !strings.Contains(err.Error(), tc.refused):
			t.Errorf("%s: refused for another reason than %q: %v", tc.name, tc.refused, err)
		}
	}
}

// The certificate is read by the identity core's rule (the identity core 0.4.2's DecodeB64url): a
// character outside base64url is a refusal, never skipped. The reader this replaced skipped it, so
// a card the core and BatonDeck refused was a card to this parser.
func TestParseCardReadsTheCertificateByTheCoresRule(t *testing.T) {
	good := testid.CardFor(t, "P", "https://p.example/mcp")
	if _, err := ParseCard(good); err != nil {
		t.Fatalf("a real card: %v", err)
	}
	bad := strings.Replace(good, "X-HDTP-CERT:", "X-HDTP-CERT:!", 1)
	if _, err := ParseCard(bad); err == nil {
		t.Fatal("ParseCard read a certificate with a character outside base64url")
	}
}

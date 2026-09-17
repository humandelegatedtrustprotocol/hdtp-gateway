package contacts

import (
	"github.com/tech-sumit/pact-gateway/internal/testid"
	"os"
	"strings"
	"testing"
)

// A card is built by pact-identity from a certificate now, so the round trip this
// used to prove — struct in, properties out — no longer exists: there are no
// X-PACT-KEY/X-PACT-ENDPOINT/X-PACT-GATEWAY properties to write. What is worth
// proving is that the parser reads a real 2.0 card and recovers the root and the
// endpoint from INSIDE the certificate rather than from any property.
func TestACardCarriesItsIdentityInTheCertificate(t *testing.T) {
	card, w, h := testid.Card(t, "Sumit Agrawal", "https://pact.sumit.example/mcp", "required")
	for _, want := range []string{"BEGIN:VCARD", "X-PACT-VERSION:2", "X-PACT-CERT:", "X-PACT-SEAL:required", "FN:Sumit Agrawal"} {
		if !strings.Contains(card, want) {
			t.Fatalf("built card missing %q:\n%s", want, card)
		}
	}
	for _, gone := range []string{"X-PACT-KEY:", "X-PACT-ENDPOINT:", "X-PACT-GATEWAY:"} {
		if strings.Contains(card, gone) {
			t.Errorf("a 2.0 card still carries %q", gone)
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

// The fixture is a real export from a phone's contacts app, and it is a 1.x card:
// folded lines, X-PACT-ENDPOINT, X-PACT-KEY. It is kept because the FOLDING is
// what it proves — a phone wraps long property values and the parser has to unfold
// them, which is as true of X-PACT-CERT as it was of X-PACT-ENDPOINT. What it can
// no longer prove is intake: this card names a generation the node does not speak.
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
	if _, err := ValidateInbound(string(raw)); err == nil {
		t.Error("a 1.x phone export was accepted at intake")
	}
}

func TestForeignCardTolerated(t *testing.T) {
	plain := "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:No Pact\r\nEND:VCARD\r\n"
	c, err := ParseCard(plain)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "" && c.Key != "" {
		t.Fatal("foreign card claimed as PACT")
	}
	if c.FN != "No Pact" {
		t.Fatalf("FN = %q", c.FN)
	}
}

func TestCardHelpersUseParser(t *testing.T) {
	card, w, _ := testid.Card(t, "Alina Rao", "https://alina.example/mcp", "required")
	if CardKey(card) != w.Fpr {
		t.Fatalf("CardKey = %q, want the root %q", CardKey(card), w.Fpr)
	}
	if CardName(card) != "Alina Rao" {
		t.Fatal("CardName no longer extracts from real cards")
	}
	if CardKey("not a card at all") != "" {
		t.Fatal("garbage input should yield empty key, not panic")
	}
	// The phone fixture is a 1.x export: a name a phone can read, and an identity
	// this node no longer accepts. CardName still works on it; CardKey cannot.
	raw, _ := os.ReadFile("testdata/iphone-export.vcf")
	if CardName(string(raw)) != "Alina Rao" {
		t.Fatal("CardName no longer reads a card exported from a phone")
	}
	if CardKey(string(raw)) != "" {
		t.Fatal("a 1.x card still yields an identity")
	}
}

func FuzzVCardParse(f *testing.F) {
	seeds := []string{
		"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nEND:VCARD\r\n",
		"BEGIN:VCARD\nVERSION:3.0\nFN:Y\nX-PACT-KEY:sha256:abc\nEND:VCARD\n",
		"", "BEGIN:VCARD", "FN:loose\r\n", "BEGIN:VCARD\r\nVERSION:4.0\r\nX-PACT-ENDPOINT:https://e\r\n x\r\nEND:VCARD\r\n",
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
			_ = CardKey(input)
		}
	})
}

// PACT §3 intake: the certificate IS the card. Strict where identity or
// reachability is at stake, tolerant where minors need room.
func TestValidateInbound(t *testing.T) {
	good, _, _ := testid.Card(t, "P", "https://p.example/mcp", "required")
	mk := func(props string) string {
		return "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:P\r\n" + props + "END:VCARD\r\n"
	}
	key := "X-PACT-KEY:sha256:abc\r\n"
	ep := "X-PACT-ENDPOINT:https://p.example/mcp\r\n"
	for _, tc := range []struct {
		name, card string
		ok         bool
	}{
		{"a 2.0 card", good, true},
		{"a 2.0 card with an unknown X- property", strings.Replace(good, "FN:P", "FN:P\r\nX-PACT-FUTURE:whatever", 1), true},
		{"major 1", mk("X-PACT-VERSION:1\r\n" + key + ep), false},
		{"no version at all", mk(key + ep), false},
		{"a 1.x minor", mk("X-PACT-VERSION:1.3\r\n" + key + ep), false},
		{"major 3", mk("X-PACT-VERSION:3\r\n" + key + ep), false},
		{"version 2 but no certificate", mk("X-PACT-VERSION:2\r\n" + key + ep), false},
		{"not a vcard at all", "hello", false},
	} {
		_, err := ValidateInbound(tc.card)
		if tc.ok && err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

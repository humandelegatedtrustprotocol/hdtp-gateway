package contacts

import (
	"os"
	"strings"
	"testing"
)

func TestBuildAndParseRoundTrip(t *testing.T) {
	in := Card{
		FN: "Sumit Agrawal", Tel: "+971 5x xxx xxxx", Email: "s@example.com",
		Endpoint: "https://pact.sumit.example/mcp",
		Key:      "sha256:VTIOhuYKFsKRCNm73quKbouEq1e5BMTyZxc65jfHmHI",
		Seal:     "required",
		Gateway:  "https://relay.example/mcp",
	}
	text, err := BuildCard(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"BEGIN:VCARD", "X-PACT-VERSION:1", "X-PACT-KEY:" + in.Key, "X-PACT-SEAL:required", "FN:Sumit Agrawal"} {
		if !strings.Contains(text, want) {
			t.Fatalf("built card missing %q:\n%s", want, text)
		}
	}
	out, err := ParseCard(text)
	if err != nil {
		t.Fatal(err)
	}
	if out.FN != in.FN || out.Tel != in.Tel || out.Email != in.Email ||
		out.Endpoint != in.Endpoint || out.Key != in.Key || out.Seal != in.Seal || out.Gateway != in.Gateway {
		t.Fatalf("round trip changed fields:\n in: %+v\nout: %+v", in, out)
	}
	if out.Version == "" || out.Key == "" {
		t.Fatal("own card not recognized as PACT")
	}
}

func TestPhoneExportedFixtureImports(t *testing.T) {
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
	// folded X-PACT-ENDPOINT line must unfold
	if c.Endpoint != "https://agent.alina.example/mcp" {
		t.Fatalf("endpoint = %q", c.Endpoint)
	}
	if c.Key != "sha256:rAGyIJ6GNU-4UyN7XeD0-rE8f8v0M6YcAZNpYX_s8Qs" || c.Seal != "required" {
		t.Fatalf("pact fields: %+v", c)
	}
	if c.Version == "" || c.Key == "" {
		t.Fatal("PACT-capable phone export not recognized")
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
	raw, _ := os.ReadFile("testdata/iphone-export.vcf")
	if CardKey(string(raw)) != "sha256:rAGyIJ6GNU-4UyN7XeD0-rE8f8v0M6YcAZNpYX_s8Qs" {
		t.Fatal("CardKey no longer extracts from real cards")
	}
	if CardName(string(raw)) != "Alina Rao" {
		t.Fatal("CardName no longer extracts from real cards")
	}
	if CardKey("not a card at all") != "" {
		t.Fatal("garbage input should yield empty key, not panic")
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

// PACT §3 intake: strict where identity or reachability is at stake, tolerant
// where minors need room.
func TestValidateInbound(t *testing.T) {
	mk := func(props string) string {
		return "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:P\r\n" + props + "END:VCARD\r\n"
	}
	key := "X-PACT-KEY:sha256:abc\r\n"
	ep := "X-PACT-ENDPOINT:https://p.example/mcp\r\n"
	gw := "X-PACT-GATEWAY:https://gw.example\r\n"
	for _, tc := range []struct {
		name, card string
		ok         bool
	}{
		{"full", mk("X-PACT-VERSION:1\r\n" + key + ep), true},
		{"no version means a 1.0 peer", mk(key + ep), true},
		{"minor versions pass", mk("X-PACT-VERSION:1.3\r\n" + key + ep), true},
		{"gateway substitutes for endpoint (relay-assisted, §10 T4)", mk(key + gw), true},
		{"no key", mk(ep), false},
		{"major 2", mk("X-PACT-VERSION:2\r\n" + key + ep), false},
		{"neither endpoint nor gateway", mk(key), false},
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

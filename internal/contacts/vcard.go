package contacts

// vCard handling (SPEC §9.3, PACT §3): a PACT card is standard vCard 4.0 plus the
// X-PACT-* properties. Parsing is tolerant — phone exports are v3.0 with folded
// lines and foreign properties — and never trusts input: callers length-cap before
// parsing, and a parse failure yields an error, never a panic.

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	govcard "github.com/emersion/go-vcard"

	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

const (
	propVersion = "X-PACT-VERSION"
	propSeal    = "X-PACT-SEAL"
	propCert    = "X-PACT-CERT"
)

// Card is the parsed view of a contact card.
type Card struct {
	FN       string
	Tel      string
	Email    string
	Version  string // X-PACT-VERSION as carried; MUST be "2"
	Endpoint string
	Key      string
	Seal     string // none|optional|required; "" = absent = none (PACT §13.4)
	// Cert is the leaf certificate the card carries (PACT §3), DER. Key is the
	// ROOT fingerprint the leaf names as its issuer and Endpoint the leaf's
	// subject alternative name — both read from the certificate, never from a
	// property, which is why the retired X-PACT-KEY/X-PACT-ENDPOINT are gone.
	Cert []byte
}

// BuildCard20 renders a 2.0 card (PACT §3): the leaf, the version, the seal.
func BuildCard20(fn string, leaf []byte, seal string) string {
	return pactidentity.EncodeCard(fn, leaf, seal, nil)
}

// ParseCard decodes the first vCard in text.
func ParseCard(text string) (Card, error) {
	dec := govcard.NewDecoder(strings.NewReader(text))
	card, err := dec.Decode()
	if err != nil {
		return Card{}, fmt.Errorf("vcard: %w", err)
	}
	get := func(name string) string {
		if f := card.Get(name); f != nil {
			return strings.TrimSpace(f.Value)
		}
		return ""
	}
	return Card{
		FN:      displayName(get(govcard.FieldFormattedName)),
		Tel:     get(govcard.FieldTelephone),
		Email:   get(govcard.FieldEmail),
		Version: get(propVersion),
		Seal:    get(propSeal),
		Cert:    pactidentity.FromB64url(get(propCert)),
	}, nil
}

// MaxDisplayName caps the peer-chosen name in runes. A formatted name longer than
// this is not a name, and the card carrying it is capped only at 16KiB.
const MaxDisplayName = 64

// displayName makes a peer's FN safe to be READ. The owner uses it to decide who
// is talking to them, so it must render as what it is: no control characters, no
// bidi overrides that repaint the text after them, no invisible padding, and no
// length that pushes the rest of a row off screen. Joiners (U+200C/U+200D) are
// kept -- Devanagari, Arabic and emoji sequences need them, and neither can hide
// or reorder anything.
//
// It never makes a name unique; two peers may still legitimately be called Alice.
// Distinguishing them is the caller's job, against the fingerprint.
func displayName(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == '\u200c' || r == '\u200d':
			return r
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		case unicode.IsSpace(r):
			return ' ' // collapsed below; a run of 200 spaces is also a layout attack
		}
		return r
	}, s)
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if r := []rune(cleaned); len(r) > MaxDisplayName {
		cleaned = string(r[:MaxDisplayName-1]) + "\u2026"
	}
	return cleaned
}

// ValidateInbound is PACT §3's intake rule, shared by every path that accepts a
// peer's card (redeem, request, accept, update). The certificate IS the card: it
// carries the root to pin, the address to reach and the validity, and the library's
// intake refuses a card with no root or no address. An expired leaf is not a
// refusal — the root and the endpoint are what a card is for. Unknown X-PACT-*
// properties pass untouched; that is how minors stay compatible.
func ValidateInbound(text string) (Card, error) {
	c, err := ParseCard(text)
	if err != nil {
		return Card{}, err
	}
	if c.Version == "" {
		return Card{}, fmt.Errorf("the card carries no X-PACT-VERSION")
	}
	if c.Version != "2" {
		return Card{}, fmt.Errorf("the card names protocol version %q; this node speaks 2 only", c.Version)
	}
	dc, err := pactidentity.DecodeCard(text, time.Now())
	if err != nil {
		return Card{}, fmt.Errorf("the card's certificate: %v", err)
	}
	c.Key, c.Endpoint, c.Cert = dc.Root, dc.Endpoint, dc.Cert
	if dc.Seal != "none" {
		c.Seal = dc.Seal
	}
	return c, nil
}

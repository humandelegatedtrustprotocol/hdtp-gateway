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
	propVersion  = "X-PACT-VERSION"
	propEndpoint = "X-PACT-ENDPOINT"
	propKey      = "X-PACT-KEY"
	propSeal     = "X-PACT-SEAL"
	propGateway  = "X-PACT-GATEWAY"
	propCert     = "X-PACT-CERT"
)

// Card is the parsed view of a contact card.
type Card struct {
	FN       string
	Tel      string
	Email    string
	Version  string // X-PACT-VERSION as carried; "1" for this protocol major
	Endpoint string
	Key      string
	Seal     string // none|optional|required; "" = absent = none (PACT §13.4)
	Gateway  string
	// Cert is the leaf certificate a 2.0 card carries (PACT §3), DER. On such a
	// card Key is the ROOT fingerprint the leaf names as its issuer and Endpoint
	// the leaf's subject alternative name — both read from the certificate,
	// never from a property, so the card's shape reads as 1.x does to callers.
	Cert []byte
}

// BuildCard20 renders a 2.0 card (PACT §3): the leaf, the version, the seal.
func BuildCard20(fn string, leaf []byte, seal string) string {
	return pactidentity.EncodeCard(fn, leaf, seal, nil)
}

// BuildCompatCard renders the compatibility card toward a peer known to be 1.x
// (PACT Appendix C): version 1, the leaf's endpoint and key fingerprint, and
// the leaf as an extra property a 2.0 receiver recognises.
func BuildCompatCard(fn string, leaf []byte, seal string) (string, error) {
	return pactidentity.EncodeCompatCard(fn, leaf, seal)
}

// BuildCard renders a PACT vCard 4.0.
func BuildCard(c Card) (string, error) {
	card := make(govcard.Card)
	card.SetValue(govcard.FieldFormattedName, c.FN)
	if c.Tel != "" {
		card.SetValue(govcard.FieldTelephone, c.Tel)
	}
	if c.Email != "" {
		card.SetValue(govcard.FieldEmail, c.Email)
	}
	card.SetValue(propVersion, "1")
	if c.Endpoint != "" {
		card.SetValue(propEndpoint, c.Endpoint)
	}
	card.SetValue(propKey, c.Key)
	if c.Seal != "" {
		card.SetValue(propSeal, c.Seal)
	}
	if c.Gateway != "" {
		card.SetValue(propGateway, c.Gateway)
	}
	govcard.ToV4(card)
	var b strings.Builder
	if err := govcard.NewEncoder(&b).Encode(card); err != nil {
		return "", fmt.Errorf("vcard: %w", err)
	}
	return b.String(), nil
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
		FN:       displayName(get(govcard.FieldFormattedName)),
		Tel:      get(govcard.FieldTelephone),
		Email:    get(govcard.FieldEmail),
		Version:  get(propVersion),
		Endpoint: get(propEndpoint),
		Key:      get(propKey),
		Seal:     get(propSeal),
		Gateway:  get(propGateway),
		Cert:     pactidentity.FromB64url(get(propCert)),
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

// ValidateInbound is PACT §3's intake rule, shared by every path that accepts
// a peer's card (redeem, request, accept, update). Strict exactly where
// identity or reachability is at stake: no key means nothing to pin, a foreign
// major version means no protocol in common, and a card with neither an
// endpoint nor a gateway names a peer that can never be reached — accepting
// any of those only defers the failure to a worse moment, far from intake.
// Unknown X-PACT-* properties pass untouched; that is how minors stay
// compatible. The outbound paths (contactinit) already enforced this; the
// inbound ones pinned on the key alone.
func ValidateInbound(text string) (Card, error) {
	c, err := ParseCard(text)
	if err != nil {
		return Card{}, err
	}
	// A 2.0 card: the certificate is the card (PACT §3). The library's intake
	// refuses what has no root to pin or no address to reach; an expired leaf
	// is not a refusal. Key and Endpoint come from the leaf.
	if c.Version == "2" {
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
	if c.Key == "" {
		return Card{}, fmt.Errorf("the card carries no X-PACT-KEY")
	}
	// The property is optional on 1.x cards; absent means 1 (a 1.0 peer).
	// Present, it must name major 1 or 2 — "3" and friends are refused.
	if v := c.Version; v != "" && v != "1" && !strings.HasPrefix(v, "1.") {
		return Card{}, fmt.Errorf("the card names protocol version %q; this node speaks 1 and 2", v)
	}
	if c.Endpoint == "" && c.Gateway == "" {
		return Card{}, fmt.Errorf("the card names neither an endpoint nor a gateway; the peer could never be reached")
	}
	return c, nil
}

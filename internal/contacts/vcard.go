package contacts

// vCard handling (SPEC §9.3, HDTP §3): an HDTP card is standard vCard 4.0 plus the
// X-HDTP-* properties. Parsing is tolerant — phone exports are v3.0 with folded
// lines and foreign properties — and never trusts input: callers length-cap before
// parsing, and a parse failure yields an error, never a panic.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	govcard "github.com/emersion/go-vcard"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

const (
	propVersion = "X-HDTP-VERSION"
	propSeal    = "X-HDTP-SEAL"
	propCert    = "X-HDTP-CERT"
)

// cardMajor is the one version a card may name here: the protocol's major (HDTP §3), as the
// identity core reads it (DecodeCard answers it as Version). TestValidateInbound holds this to what
// the core answers for a built card: were the two to differ, the refusal would name another version
// than the one this node takes.
const cardMajor = "1"

// Card is the parsed view of a contact card.
type Card struct {
	FN       string
	Tel      string
	Email    string
	Version  string // X-HDTP-VERSION as carried; ValidateInbound takes cardMajor and no other
	Endpoint string
	Key      string
	Seal     string // none|optional|required; "" = absent = none (HDTP §13.4)
	// Cert is the leaf certificate the card carries (HDTP §3), DER. Key is the
	// ROOT fingerprint the leaf names as its issuer and Endpoint the leaf's
	// subject alternative name — both read from the certificate, never from a
	// property of the card.
	Cert []byte
}

// BuildCard renders a card (HDTP §3): the leaf, the version, the seal. It refuses a name or a
// seal that carries a control character (HDTP §3): a card is lines, and a line break in a
// display name wrote a property of the name's choosing into the card this node serves.
func BuildCard(fn string, leaf []byte, seal string) (string, error) {
	return hdtpidentity.EncodeCard(fn, leaf, seal, nil)
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
	// The certificate is read by the rule the identity core reads it with (hdtp-identity's
	// DecodeB64url: the padding and the standard alphabet forgiven, nothing else), so a card the
	// core refuses does not read here either. An absent property is no certificate, not a
	// refusal; the library's intake, behind ValidateInbound, refuses a card without one.
	cert, err := hdtpidentity.DecodeB64url(get(propCert))
	if err != nil {
		return Card{}, fmt.Errorf("vcard: %s is not base64url", propCert)
	}
	return Card{
		FN:      displayName(get(govcard.FieldFormattedName)),
		Tel:     get(govcard.FieldTelephone),
		Email:   get(govcard.FieldEmail),
		Version: get(propVersion),
		Seal:    get(propSeal),
		Cert:    cert,
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

// SealOf is the X-HDTP-SEAL policy of a contact this node holds, read off the card on file the way
// the identity core reads a card (hdtpidentity.DecodeCard), so the node and the core have one
// reading: the property's value, and `none` for a card with no such line (HDTP §3: "Absent =
// none"; §13.4: "senders MUST NOT seal").
//
//   - A card on file that does not read is an error. Its policy is not known, and neither guess is
//     safe on the wire: a call sealed to a `none` recipient is one it said not to send, and a
//     plaintext call to a `required` one is refused `seal_required`.
//   - No card on file is a contact written without one. Two paths write such a row: an import,
//     whose contacts.csv carries neither a card nor a policy (HDTP §9.2), and the owner approving a
//     root that returned after a removal (DecideAddress), which re-adds it from the pending
//     address — a leaf and an endpoint, no card. It is sealed to, as such a contact always was
//     here: the SPEC does not say what a host assumes for it, and that is named as a gap in the
//     node's docs/release/port-parity-2026-09-29.md.
func SealOf(card string, now time.Time) (string, error) {
	if card == "" {
		return "required", nil
	}
	dc, err := hdtpidentity.DecodeCard(card, now)
	if err != nil {
		return "", fmt.Errorf("the card on file does not read (%v), so its sealing policy is not known", err)
	}
	return dc.Seal, nil
}

// ValidateInbound is HDTP §3's intake rule, shared by every path that accepts a
// peer's card (redeem, request, accept, update). The certificate IS the card: it
// carries the root to pin, the address to reach and the validity, and the library's
// intake refuses a card with no root or no address. An expired leaf is not a
// refusal — the root and the endpoint are what a card is for. Unknown X-HDTP-*
// properties pass untouched; that is how minors stay compatible.
//
// The card is read ONCE, by the identity core (hdtpidentity.DecodeCard), the reading every door of
// the node and the cloud shares: its §3 "Reading a card" takes a certificate whose folding a paste
// damaged (continuations without their leading space, blank lines between them). ParseCard read it
// first here, and refused it before the core saw it: go-vcard drops a line with no colon, so the
// certificate it handed over was cut, and `X-HDTP-CERT is not base64url`. Nothing on the result comes
// from another parser: the name, the version, the seal, the certificate, the root and the endpoint
// are the core's.
func ValidateInbound(text string) (Card, error) {
	dc, err := hdtpidentity.DecodeCard(text, time.Now())
	if err != nil {
		var ce hdtpidentity.CardError
		if errors.As(err, &ce) {
			switch ce.Why {
			case "no X-HDTP-VERSION":
				return Card{}, fmt.Errorf("the card carries no X-HDTP-VERSION")
			case "version not implemented":
				return Card{}, fmt.Errorf("the card names a protocol version this node does not speak; it speaks %s only", cardMajor)
			}
		}
		return Card{}, fmt.Errorf("the card's certificate: %w", err)
	}
	c := Card{
		FN: displayName(dc.FN), Version: strconv.Itoa(dc.Version),
		Key: dc.Root, Endpoint: dc.Endpoint, Cert: dc.Cert,
	}
	if dc.Seal != "none" {
		c.Seal = dc.Seal
	}
	return c, nil
}

// CertificateUnreadable is whether ValidateInbound refused a card because its certificate does not
// read: the refusal a person who pasted a card can act on, by sending the card's file or its invite
// link, which no copy-and-paste can damage.
func CertificateUnreadable(err error) bool {
	var ce hdtpidentity.CardError
	return errors.As(err, &ce) && strings.HasPrefix(ce.Why, "certificate does not parse")
}

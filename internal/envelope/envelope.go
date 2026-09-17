// Package envelope carries the sealed-envelope WIRE CONTAINER (PACT §13.1): the
// four members an envelope is made of, their base64url encoding, the protected
// header's shape, and the `envelope_invalid` error every malformation maps to.
//
// It used to carry the crypto too — HPKE seal/open, the detached signature, the
// suite helpers — for the `v: 1` generation. That generation is gone, and `v: 2`
// sealing lives in pact-identity, which both this node and the wallet share. What
// is left is the part that is genuinely this node's: the shape on the wire.
package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	SuiteP256   = "PACT-SEAL-P256"
	SuiteX25519 = "PACT-SEAL-X25519"

	CTYCall   = "application/pact-call+json"
	CTYResult = "application/pact-result+json"
)

// ErrInvalid is the wire-facing failure: every malformed, misdirected, mis-signed,
// or undecryptable envelope maps to it (PACT §12 `envelope_invalid`).
var ErrInvalid = errors.New("envelope_invalid")

// Envelope wire members; in Go they are raw bytes, on the wire unpadded base64url.
type Envelope struct {
	Protected []byte // canonical-JSON header bytes (also the HPKE AAD)
	Enc       []byte // HPKE encapsulated key
	CT        []byte // ciphertext
	Sig       []byte // detached signature over Protected‖Enc‖CT
}

type wireEnvelope struct {
	Protected string `json:"protected"`
	Enc       string `json:"enc"`
	CT        string `json:"ct"`
	Sig       string `json:"sig"`
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	enc := base64.RawURLEncoding.EncodeToString
	return json.Marshal(wireEnvelope{
		Protected: enc(e.Protected), Enc: enc(e.Enc), CT: enc(e.CT), Sig: enc(e.Sig),
	})
}

func (e *Envelope) UnmarshalJSON(b []byte) error {
	var w wireEnvelope
	if err := json.Unmarshal(b, &w); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	dec := base64.RawURLEncoding.DecodeString
	var err error
	if e.Protected, err = dec(w.Protected); err == nil {
		if e.Enc, err = dec(w.Enc); err == nil {
			if e.CT, err = dec(w.CT); err == nil {
				e.Sig, err = dec(w.Sig)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// Header is the protected header (PACT §13.1). Field declaration order IS the
// canonical (lexicographic) key order; the encoder preserves it.
type Header struct {
	CTY   string `json:"cty"`
	Exp   int64  `json:"exp"`
	KID   string `json:"kid"`
	MsgID string `json:"msg_id"`
	Suite string `json:"suite"`
	TS    int64  `json:"ts"`
	V     int    `json:"v"`
}

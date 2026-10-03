// Package envelope carries what this node says about a sealed envelope (HDTP §13.1) beyond the
// wire object itself: the protected header's shape, which the node reads once the library has
// decided the envelope, and the `envelope_invalid` error every malformation maps to.
//
// The wire object — the four members and their one spelling — is hdtp-identity's `Envelope`,
// which the library decides as it arrives. This package used to decode the members itself, with a
// lenient decoder, and hand the library a canonical re-encoding, so the library's one-spelling
// refusal never ran; and it used to carry the retired generation's crypto, which is gone.
package envelope

import "errors"

// ErrInvalid is the wire-facing failure: every malformed, misdirected, mis-signed,
// or undecryptable envelope maps to it (HDTP §12 `envelope_invalid`).
var ErrInvalid = errors.New("envelope_invalid")

// Header is the protected header (HDTP §13.1). Field declaration order IS the
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

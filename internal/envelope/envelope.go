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

// Header is the protected header of a sealed envelope (HDTP §13.1), the member the sealing
// binds as the HPKE AAD. The node only decodes it: internal/public unmarshals it from the
// envelope's `protected` member after hdtp-identity's Decide has read those same bytes and
// decided on them, so a field here is never evidence that the library accepted the header.
// This package holds no encoder. The fields are declared in the header's lexicographic key
// order.
type Header struct {
	// CTY is the direction: application/hdtp-call+json for a request, application/hdtp-result+json for a result.
	CTY string `json:"cty"`
	// Exp is the expiry in Unix seconds; the replay record is kept only until min(Exp, TS + skew + 1).
	Exp int64 `json:"exp"`
	// KID is the fingerprint of the recipient leaf key the envelope is sealed to.
	KID string `json:"kid"`
	// MsgID is the envelope's idempotency key, a separate namespace from the inner call's msg_id.
	MsgID string `json:"msg_id"`
	// Suite is the sealing suite, which follows the recipient's key.
	Suite string `json:"suite"`
	// TS is the sender's clock, in Unix seconds, when it sealed.
	TS int64 `json:"ts"`
	// V is the header version; every envelope this node opens is v 1 (HDTP §13.1).
	V int `json:"v"`
}

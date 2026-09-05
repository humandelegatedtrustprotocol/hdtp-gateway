// Package envelope implements PACT sealed envelopes (SPEC §4, PACT §13):
// HPKE Base mode to the recipient's identity key plus a detached signature by the
// sender's identity key over protected‖enc‖ct. Pinned parameters (PACT §13.1):
// canonical-JSON protected header (sorted keys, no insignificant whitespace, no HTML
// escaping) whose raw bytes are the HPKE AAD; HPKE info = "PACT-SEAL-v1"; ECDSA
// signatures are ASN.1 DER, Ed25519 signatures are pure RFC 8032; Ed25519 identities
// convert to X25519 via RFC 7748 §4.1 (public) and RFC 8032 §5.1.5 (private scalar).
package envelope

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

const (
	SuiteP256   = "PACT-SEAL-P256"
	SuiteX25519 = "PACT-SEAL-X25519"

	CTYCall   = "application/pact-call+json"
	CTYResult = "application/pact-result+json"

	hpkeInfo = "PACT-SEAL-v1"
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
	From  string `json:"from"`
	KID   string `json:"kid"`
	MsgID string `json:"msg_id"`
	Suite string `json:"suite"`
	To    string `json:"to"`
	TS    int64  `json:"ts"`
	V     int    `json:"v"`
}

func canonicalHeader(h Header) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(h); err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// ParseHeader decodes and structurally validates the protected header.
func ParseHeader(e *Envelope) (Header, error) {
	var h Header
	dec := json.NewDecoder(strings.NewReader(string(e.Protected)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return Header{}, fmt.Errorf("%w: header: %v", ErrInvalid, err)
	}
	if h.V != 1 {
		return Header{}, fmt.Errorf("%w: unsupported version %d", ErrInvalid, h.V)
	}
	if h.Suite != SuiteP256 && h.Suite != SuiteX25519 {
		return Header{}, fmt.Errorf("%w: unsupported suite %q", ErrInvalid, h.Suite)
	}
	return h, nil
}

type SealParams struct {
	Sender       *identity.Keypair
	RecipientPub crypto.PublicKey
	To           string // recipient fingerprint
	MsgID        string
	TS, Exp      int64
	CTY          string
}

// Seal builds an envelope: suite chosen by the recipient's key type, AAD = the
// canonical header bytes, signature over Protected‖Enc‖CT by the sender's key.
func Seal(p SealParams, plaintext []byte) (*Envelope, error) {
	return SealSeeded(p, plaintext, rand.Reader)
}

// SealSeeded is Seal with injectable randomness — production always passes
// crypto/rand via Seal; the deterministic test-vector generator passes a DRBG.
func SealSeeded(p SealParams, plaintext []byte, rng io.Reader) (*Envelope, error) {
	suiteID, kemPub, err := recipientKEM(p.RecipientPub)
	if err != nil {
		return nil, err
	}
	h := Header{
		CTY: p.CTY, Exp: p.Exp, From: p.Sender.Fingerprint, KID: p.To,
		MsgID: p.MsgID, Suite: suiteID, To: p.To, TS: p.TS, V: 1,
	}
	protected, err := canonicalHeader(h)
	if err != nil {
		return nil, err
	}
	suite := hpkeSuite(suiteID)
	sender, err := suite.NewSender(kemPub, []byte(hpkeInfo))
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	enc, sealer, err := sender.Setup(rng)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	ct, err := sealer.Seal(plaintext, protected)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	sig, err := sign(p.Sender, sigInput(protected, enc, ct), rng)
	if err != nil {
		return nil, err
	}
	return &Envelope{Protected: protected, Enc: enc, CT: ct, Sig: sig}, nil
}

// Open decrypts an envelope addressed to the recipient. It does NOT verify the
// signature — VerifySig is a separate step so the §4.4 pipeline (P1-04) can order
// resolution, opening, and verification per spec.
func Open(recipient *identity.Keypair, e *Envelope) ([]byte, error) {
	h, err := ParseHeader(e)
	if err != nil {
		return nil, err
	}
	kemPriv, err := recipientKEMPrivate(recipient, h.Suite)
	if err != nil {
		return nil, err
	}
	suite := hpkeSuite(h.Suite)
	receiver, err := suite.NewReceiver(kemPriv, []byte(hpkeInfo))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	opener, err := receiver.Setup(e.Enc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	pt, err := opener.Open(e.CT, e.Protected)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt failed", ErrInvalid)
	}
	return pt, nil
}

func sigInput(protected, enc, ct []byte) []byte {
	out := make([]byte, 0, len(protected)+len(enc)+len(ct))
	out = append(out, protected...)
	out = append(out, enc...)
	return append(out, ct...)
}

func sign(kp *identity.Keypair, msg []byte, rng io.Reader) ([]byte, error) {
	switch k := kp.Signer.(type) {
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256(msg)
		sig, err := ecdsa.SignASN1(rng, k, sum[:]) // pinned: ASN.1 DER
		if err != nil {
			return nil, fmt.Errorf("envelope: %w", err)
		}
		return sig, nil
	case ed25519.PrivateKey:
		return ed25519.Sign(k, msg), nil // pinned: pure Ed25519 (RFC 8032)
	default:
		return nil, fmt.Errorf("envelope: unsupported signer %T", kp.Signer)
	}
}

// VerifySig checks the detached signature under the claimed sender's public key.
func VerifySig(e *Envelope, senderPub crypto.PublicKey) error {
	msg := sigInput(e.Protected, e.Enc, e.CT)
	switch pk := senderPub.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(pk, sum[:], e.Sig) {
			return fmt.Errorf("%w: bad signature", ErrInvalid)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, msg, e.Sig) {
			return fmt.Errorf("%w: bad signature", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported sender key %T", ErrInvalid, senderPub)
	}
	return nil
}

/* ------------------------- KEM key plumbing ------------------------- */

func hpkeSuite(id string) hpke.Suite {
	if id == SuiteX25519 {
		return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
	}
	return hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
}

// recipientKEM maps a recipient identity public key to (suite, HPKE public key).
func recipientKEM(pub crypto.PublicKey) (string, kem.PublicKey, error) {
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		raw := ellipticMarshal(pk)
		k, err := hpke.KEM_P256_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(raw)
		if err != nil {
			return "", nil, fmt.Errorf("envelope: %w", err)
		}
		return SuiteP256, k, nil
	case ed25519.PublicKey:
		x, err := ed25519PubToX25519(pk)
		if err != nil {
			return "", nil, err
		}
		k, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(x)
		if err != nil {
			return "", nil, fmt.Errorf("envelope: %w", err)
		}
		return SuiteX25519, k, nil
	default:
		return "", nil, fmt.Errorf("envelope: unsupported recipient key %T", pub)
	}
}

// recipientKEMPrivate maps the recipient's identity private key to the suite's KEM key.
func recipientKEMPrivate(kp *identity.Keypair, suiteID string) (kem.PrivateKey, error) {
	switch k := kp.Signer.(type) {
	case *ecdsa.PrivateKey:
		if suiteID != SuiteP256 {
			return nil, fmt.Errorf("%w: suite/key mismatch", ErrInvalid)
		}
		raw := make([]byte, 32)
		k.D.FillBytes(raw)
		priv, err := hpke.KEM_P256_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return priv, nil
	case ed25519.PrivateKey:
		if suiteID != SuiteX25519 {
			return nil, fmt.Errorf("%w: suite/key mismatch", ErrInvalid)
		}
		scalar := ed25519PrivToX25519(k)
		priv, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPrivateKey(scalar)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("%w: unsupported recipient key %T", ErrInvalid, kp.Signer)
	}
}

// ellipticMarshal renders the uncompressed SEC1 point (what the P-256 KEM consumes).
func ellipticMarshal(pk *ecdsa.PublicKey) []byte {
	byteLen := 32
	out := make([]byte, 1+2*byteLen)
	out[0] = 4
	pk.X.FillBytes(out[1 : 1+byteLen])
	pk.Y.FillBytes(out[1+byteLen:])
	return out
}

// ed25519PubToX25519: RFC 7748 §4.1 birational map, via edwards25519.
func ed25519PubToX25519(pk ed25519.PublicKey) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, fmt.Errorf("%w: bad ed25519 point", ErrInvalid)
	}
	return p.BytesMontgomery(), nil
}

// ed25519PrivToX25519: RFC 8032 §5.1.5 — SHA-512 of the seed, clamped, is the
// X25519 scalar corresponding to the converted public key.
func ed25519PrivToX25519(k ed25519.PrivateKey) []byte {
	h := sha512.Sum512(k.Seed())
	scalar := h[:32]
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar
}

// jsonUnmarshal is a tiny indirection so vectors.go avoids importing encoding/json
// twice under different names during codegen-free builds.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// SuiteForKey names the suite an account with this key type accepts (§4.4 step
// 2: the suite MUST match the addressed account's key type).
func SuiteForKey(kp *identity.Keypair) string {
	if _, ok := kp.Signer.(ed25519.PrivateKey); ok {
		return SuiteX25519
	}
	return SuiteP256
}

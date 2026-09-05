package envelope

// Deterministic test-vector generation (SPEC §14.1, PACT §13.5). Everything derives
// from one documented seed: keys and all sealing randomness come from a SHA-256
// counter DRBG over "PACT-SEAL-vectors-1", so `go run ./internal/envelope/cmd/genvectors`
// reproduces testdata/vectors.json byte for byte. The vectors are openable by ANY
// implementation: each carries the PKCS#8 keys, the four wire members, and the
// expected plaintext — determinism is only needed to regenerate, never to open.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

const vectorSeed = "PACT-SEAL-vectors-1"

// drbg is a SHA-256 counter DRBG — NOT for production use; vectors only.
type drbg struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func newDRBG(context string) *drbg {
	sum := sha256.Sum256([]byte(vectorSeed + "/" + context))
	return &drbg{seed: sum[:]}
}

func (d *drbg) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], d.ctr)
		d.ctr++
		block := sha256.Sum256(append(d.seed, ctr[:]...))
		d.buf = append(d.buf, block[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// Vector is one committed test case.
type Vector struct {
	Name         string `json:"name"`
	Suite        string `json:"suite"`
	SenderKeyHex string `json:"sender_key_pkcs8_hex"`
	RecipKeyHex  string `json:"recipient_key_pkcs8_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	Protected    string `json:"protected"` // b64url, as on the wire
	Enc          string `json:"enc"`
	CT           string `json:"ct"`
	Sig          string `json:"sig"`
}

// vectorKeypair derives keys from DRBG output DIRECTLY — Go's ecdsa.GenerateKey
// is deliberately reader-nondeterministic (randutil.MaybeReadByte), so the scalar
// is taken from the stream and the key built by scalar multiplication.
func vectorKeypair(algo identity.Algo, context string) (*identity.Keypair, error) {
	rng := newDRBG("key/" + context)
	switch algo {
	case identity.AlgoP256:
		curve := elliptic.P256()
		n := curve.Params().N
		var d *big.Int
		for {
			raw := make([]byte, 32)
			if _, err := io.ReadFull(rng, raw); err != nil {
				return nil, err
			}
			d = new(big.Int).SetBytes(raw)
			if d.Sign() > 0 && d.Cmp(n) < 0 {
				break
			}
		}
		x, y := curve.ScalarBaseMult(d.Bytes())
		k := &ecdsa.PrivateKey{D: d, PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}}
		fpr, err := identity.Fingerprint(k.Public())
		if err != nil {
			return nil, err
		}
		return &identity.Keypair{Algo: algo, Signer: k, Fingerprint: fpr}, nil
	case identity.AlgoEd25519:
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(rng, seed); err != nil {
			return nil, err
		}
		k := ed25519.NewKeyFromSeed(seed)
		fpr, err := identity.Fingerprint(k.Public())
		if err != nil {
			return nil, err
		}
		return &identity.Keypair{Algo: algo, Signer: k, Fingerprint: fpr}, nil
	}
	return nil, fmt.Errorf("unknown algo %s", algo)
}

// GenerateVectors produces the four cross-curve cases deterministically.
func GenerateVectors() ([]Vector, error) {
	pairs := []struct {
		name      string
		sender    identity.Algo
		recipient identity.Algo
	}{
		{"p256-to-p256", identity.AlgoP256, identity.AlgoP256},
		{"p256-to-ed25519", identity.AlgoP256, identity.AlgoEd25519},
		{"ed25519-to-p256", identity.AlgoEd25519, identity.AlgoP256},
		{"ed25519-to-ed25519", identity.AlgoEd25519, identity.AlgoEd25519},
	}
	var out []Vector
	for _, p := range pairs {
		sender, err := vectorKeypair(p.sender, p.name+"/sender")
		if err != nil {
			return nil, err
		}
		recip, err := vectorKeypair(p.recipient, p.name+"/recipient")
		if err != nil {
			return nil, err
		}
		plaintext := []byte(`{"method":"tools/call","params":{"name":"send_message","arguments":{"msg_id":"vec-1","text":"hello from the PACT test vectors"}}}`)
		env, err := SealSeeded(SealParams{
			Sender: sender, RecipientPub: recip.Signer.Public(), To: recip.Fingerprint,
			MsgID: "vec-" + p.name, TS: 1756000000, Exp: 1756000600, CTY: CTYCall,
		}, plaintext, newDRBG("seal/"+p.name))
		if err != nil {
			return nil, err
		}
		sDER, err := x509.MarshalPKCS8PrivateKey(sender.Signer)
		if err != nil {
			return nil, err
		}
		rDER, err := x509.MarshalPKCS8PrivateKey(recip.Signer)
		if err != nil {
			return nil, err
		}
		wire, err := env.MarshalJSON()
		if err != nil {
			return nil, err
		}
		var w wireEnvelope
		if err := unmarshalStrict(wire, &w); err != nil {
			return nil, err
		}
		out = append(out, Vector{
			Name: p.name, Suite: mustSuite(env), SenderKeyHex: hex.EncodeToString(sDER),
			RecipKeyHex: hex.EncodeToString(rDER), PlaintextHex: hex.EncodeToString(plaintext),
			Protected: w.Protected, Enc: w.Enc, CT: w.CT, Sig: w.Sig,
		})
	}
	return out, nil
}

func unmarshalStrict(b []byte, w *wireEnvelope) error {
	return jsonUnmarshal(b, w)
}

func mustSuite(e *Envelope) string {
	h, err := ParseHeader(e)
	if err != nil {
		panic(err)
	}
	return h.Suite
}

var _ io.Reader = (*drbg)(nil)

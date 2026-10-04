package testid

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"filippo.io/edwards25519"
)

// SmallOrderR signs msg with priv the way RFC 8032 does, except that the nonce is zero: R is the
// identity point, of small order, and S = k·a. crypto/ed25519's Verify accepts the result — [S]B
// equals R + [k]A — while the identity core's VerifyDetached refuses any R of small order, as the
// Rust core's verify_strict does (HDTP §13.1). Only the holder of priv can make one, so it is the
// shape a host's own non-canonical signature takes: one key, two signatures over one card.
func SmallOrderR(t testing.TB, priv ed25519.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := sha512.Sum512(priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatalf("testid: scalar: %v", err)
	}
	r := edwards25519.NewIdentityPoint().Bytes()
	pub := priv.Public().(ed25519.PublicKey)
	d := sha512.New()
	d.Write(r)
	d.Write(pub)
	d.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(d.Sum(nil))
	if err != nil {
		t.Fatalf("testid: challenge: %v", err)
	}
	s := edwards25519.NewScalar().Multiply(k, a)
	sig := append(append([]byte{}, r...), s.Bytes()...)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("testid: the small-order signature does not verify under crypto/ed25519, so it proves nothing")
	}
	return sig
}

// SpareBits is the same bytes as an unpadded base64url string, spelled a second way: the last
// character's unused low bits set. A non-strict decoder reads both spellings as one byte string.
func SpareBits(t testing.TB, b64 string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if (len(b64)*6)%8 == 0 { // the unused low bits of the last character

		t.Fatalf("testid: %d characters leave no spare bits", len(b64))
	}
	last := len(b64) - 1
	i := 0
	for i < len(alphabet) && alphabet[i] != b64[last] {
		i++
	}
	out := b64[:last] + string(alphabet[i|1])
	a, aerr := base64.RawURLEncoding.DecodeString(b64)
	b, berr := base64.RawURLEncoding.DecodeString(out)
	if aerr != nil || berr != nil || string(a) != string(b) || out == b64 {
		t.Fatal("testid: no second spelling of the same bytes")
	}
	return out
}

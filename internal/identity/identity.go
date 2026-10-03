// Package identity holds what this host has of an account's identity (SPEC §3, HDTP §2): the
// account's keypair — P-256 default, Ed25519 permitted — and, once a wallet has certified it,
// the leaf and the root above it. The identity is the root, whose key this node never holds;
// the key here presents the chain as its TLS certificate and signs sealed envelopes.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
	"math/big"
	"time"
)

type Algo string

const (
	AlgoP256    Algo = "p256"
	AlgoEd25519 Algo = "ed25519"
)

type Keypair struct {
	Algo        Algo
	Signer      crypto.Signer
	Fingerprint string
	// When the key is a leaf's: the leaf and the root that issued it, DER (HDTP §2, §14).
	// Both empty for a key the wallet has not certified, which can present nothing and
	// speak for nobody. HasChain is the question.
	Leaf, Root []byte
}

// HasChain reports whether this key is a certified leaf's: it holds the leaf and the root
// above it, which is what lets it present a chain and sign as the identity (HDTP §2).
func (k *Keypair) HasChain() bool { return k != nil && len(k.Leaf) > 0 && len(k.Root) > 0 }

// Fingerprint computes HDTP §2's identity over the PKIX/SPKI DER encoding of the public key:
// the library's Fingerprint, "sha256:" + base64url(SHA-256(SPKI)), unpadded.
func Fingerprint(pub crypto.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}
	return hdtpidentity.Fingerprint(spki), nil
}

// Generate draws a fresh key with the library's GenerateKey. Its algorithm names are this
// package's (AlgoP256 is hdtpidentity.AlgP256, AlgoEd25519 is hdtpidentity.AlgEd25519; a test
// holds them equal), and the key the library draws becomes a crypto.Signer here.
func Generate(algo Algo) (*Keypair, error) {
	if algo != AlgoP256 && algo != AlgoEd25519 {
		return nil, fmt.Errorf("identity: unknown algorithm %q (want p256|ed25519)", algo)
	}
	k, err := hdtpidentity.GenerateKey(string(algo))
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return FromLib(k)
}

// SelfSignedCert issues the account's long-lived self-signed certificate
// (HDTP §2: chain irrelevant, CN free-form; 10-year validity).
func SelfSignedCert(kp *Keypair, cn string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, kp.Signer.Public(), kp.Signer)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return der, nil
}

// MarshalPKCS8 serializes the private key for sealed at-rest storage (SPEC §3.7).
func MarshalPKCS8(kp *Keypair) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(kp.Signer)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return der, nil
}

// ParsePKCS8 restores a keypair from its PKCS#8 DER.
func ParsePKCS8(der []byte) (*Keypair, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	var kp Keypair
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		kp = Keypair{Algo: AlgoP256, Signer: k}
	case ed25519.PrivateKey:
		kp = Keypair{Algo: AlgoEd25519, Signer: k}
	default:
		return nil, fmt.Errorf("identity: unsupported key type %T", key)
	}
	fpr, err := Fingerprint(kp.Signer.Public())
	if err != nil {
		return nil, err
	}
	kp.Fingerprint = fpr
	return &kp, nil
}

// VerifyBytes checks a signature made by signBytes' conventions (ECDSA ASN.1
// DER over SHA-256, or pure Ed25519) against a public key — the verifier side
// of card signatures.
func VerifyBytes(pub crypto.PublicKey, msg, sig []byte) bool {
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pk, sum[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pk, msg, sig)
	default:
		return false
	}
}

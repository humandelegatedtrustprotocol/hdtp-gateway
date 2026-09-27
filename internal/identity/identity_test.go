package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// loadFixture parses a committed PKCS#8 PEM and its openssl-computed fingerprint.
func loadFixture(t *testing.T, keyFile, fprFile string) (any, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + keyFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/" + fprFile)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(want)
}

func TestFingerprintMatchesOpenSSLFixture(t *testing.T) {
	key, want := loadFixture(t, "p256.pem", "p256.fingerprint")
	got, err := Fingerprint(key.(*ecdsa.PrivateKey).Public())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("P-256 fingerprint mismatch:\n got %s\nwant %s", got, want)
	}
	key2, want2 := loadFixture(t, "ed25519.pem", "ed25519.fingerprint")
	got2, err := Fingerprint(key2.(ed25519.PrivateKey).Public())
	if err != nil {
		t.Fatal(err)
	}
	if got2 != want2 {
		t.Fatalf("Ed25519 fingerprint mismatch:\n got %s\nwant %s", got2, want2)
	}
}

func TestFingerprintFormat(t *testing.T) {
	kp, err := Generate(AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.Fingerprint, "sha256:") {
		t.Fatalf("fingerprint prefix: %s", kp.Fingerprint)
	}
	rest := strings.TrimPrefix(kp.Fingerprint, "sha256:")
	if strings.ContainsAny(rest, "+/=") || len(rest) != 43 {
		t.Fatalf("not unpadded base64url SHA-256: %q", rest)
	}
}

func TestGenerateBothAlgos(t *testing.T) {
	for _, algo := range []Algo{AlgoP256, AlgoEd25519} {
		kp, err := Generate(algo)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		if kp.Algo != algo || kp.Fingerprint == "" || kp.Signer == nil {
			t.Fatalf("%s: incomplete keypair %+v", algo, kp)
		}
	}
	if _, err := Generate("rsa"); err == nil {
		t.Fatal("unknown algo accepted")
	}
}

func TestSelfSignedCertPresentsSameSPKI(t *testing.T) {
	kp, err := Generate(AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := SelfSignedCert(kp, "Work Account")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	// PACT §2: identity is the SPKI fingerprint of the presented certificate.
	got, err := Fingerprint(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != kp.Fingerprint {
		t.Fatalf("cert SPKI %s != keypair %s", got, kp.Fingerprint)
	}
	if cert.Subject.CommonName != "Work Account" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if !cert.NotAfter.After(cert.NotBefore.AddDate(9, 0, 0)) {
		t.Fatal("cert should be long-lived (~10y)")
	}
	// usable as a tls.Certificate
	tc := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: kp.Signer}
	if len(tc.Certificate) != 1 {
		t.Fatal("tls wrap failed")
	}
}

func TestPKCS8RoundTrip(t *testing.T) {
	for _, algo := range []Algo{AlgoP256, AlgoEd25519} {
		kp, _ := Generate(algo)
		der, err := MarshalPKCS8(kp)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParsePKCS8(der)
		if err != nil {
			t.Fatal(err)
		}
		if back.Fingerprint != kp.Fingerprint || back.Algo != kp.Algo {
			t.Fatalf("%s: round trip changed identity: %s != %s", algo, back.Fingerprint, kp.Fingerprint)
		}
	}
}

// Generate is the library's GenerateKey. What could differ between the two is the SPKI: the
// fingerprint is computed over the bytes the library holds, and a certificate presents the bytes
// crypto/x509 marshals. They must be one encoding for both algorithms, or a key would present
// itself under a fingerprint nobody computed for it. The names are held equal too, since this
// package passes its own to the library.
func TestGenerateIsTheLibrarysKeyUnderOneSPKI(t *testing.T) {
	if string(AlgoP256) != pactidentity.AlgP256 || string(AlgoEd25519) != pactidentity.AlgEd25519 {
		t.Fatalf("algorithm names drifted: %q/%q vs %q/%q", AlgoP256, AlgoEd25519, pactidentity.AlgP256, pactidentity.AlgEd25519)
	}
	for _, algo := range []Algo{AlgoP256, AlgoEd25519} {
		kp, err := Generate(algo)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(kp.Signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		pub, err := pactidentity.ParseSPKI(spki)
		if err != nil {
			t.Fatalf("%s: the library does not read what x509 marshals: %v", algo, err)
		}
		if got, _ := pactidentity.AlgorithmOf(pub); got != string(algo) {
			t.Fatalf("%s: the library reads it as %q", algo, got)
		}
		if want := pactidentity.Fingerprint(spki); kp.Fingerprint != want {
			t.Fatalf("%s: fingerprint %s is not the one over the SPKI a certificate presents (%s)", algo, kp.Fingerprint, want)
		}
		if f, _ := Fingerprint(kp.Signer.Public()); f != kp.Fingerprint {
			t.Fatalf("%s: Fingerprint(public) %s disagrees with Generate's %s", algo, f, kp.Fingerprint)
		}
	}
	if _, err := Generate("rsa"); err == nil {
		t.Fatal("an algorithm the profile does not admit was generated")
	}
}

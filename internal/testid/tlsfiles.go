package testid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ServerFiles writes a self-signed server certificate for name and its key into dir, as PEM files
// named <prefix>.crt and <prefix>.key, the shape an operator hands `internal_tls_cert` and
// `internal_tls_key`. It returns both paths and the certificate. Not a HDTP certificate: the
// internal surface's TLS is ordinary web TLS (SPEC §8.3).
func ServerFiles(tb testing.TB, dir, prefix, name string) (certFile, keyFile string, cert *x509.Certificate) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	if cert, err = x509.ParseCertificate(der); err != nil {
		tb.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, prefix+".crt"), filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		tb.Fatal(err)
	}
	return certFile, keyFile, cert
}

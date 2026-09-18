package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

func accountClient(t *testing.T) *Client {
	t.Helper()
	kp, err := identity.Generate(identity.AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := identity.SelfSignedCert(kp, "me")
	if err != nil {
		t.Fatal(err)
	}
	return &Client{
		Keypair: kp,
		Cert:    tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer},
	}
}

// startTLS starts a raw TLS server; handshake results are reported over got.
func startTLS(t *testing.T, conf *tls.Config, got chan<- []*x509.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := tls.Server(c, conf)
			if err := tc.Handshake(); err == nil {
				got <- tc.ConnectionState().PeerCertificates
			} else {
				got <- nil
			}
			tc.Close()
		}
	}()
	return ln.Addr().String()
}

// TestClientCertSentDespiteCAList: the edge-style CertificateRequest advertises a CA
// our self-signed cert cannot satisfy; Go's default selection would send nothing —
// the client MUST send anyway (SPEC §10, GetClientCertificate).
func TestClientCertSentDespiteCAList(t *testing.T) {
	// server with a random CA in its ClientCAs (advertised in CertificateRequest)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SomeEdgeCA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// The server presents a real chain: a self-signed certificate is not an
	// identity under 2.0, so pinning one would refuse the dial before the thing
	// this test is about — which certificate the CLIENT sends — could be observed.
	server := newIdentity20(t, "Bharat", "https://agent.bharat.example/mcp")
	got := make(chan []*x509.Certificate, 1)
	addr := startTLS(t, &tls.Config{
		Certificates: []tls.Certificate{server.tlsCert()},
		ClientAuth:   tls.RequestClientCert, // request with CA list, don't verify
		ClientCAs:    pool,
	}, got)

	c := accountClient(t)
	conn, err := tls.Dial("tcp", addr, c.tlsConfig(server.peerOf(), "agent.bharat.example"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	certs := <-got
	if len(certs) == 0 {
		t.Fatal("client sent no certificate when CertificateRequest advertised a foreign CA")
	}
	fpr, _ := identity.Fingerprint(certs[0].PublicKey)
	if fpr != c.Keypair.Fingerprint {
		t.Fatalf("wrong cert sent: %s", fpr)
	}
}

// A self-signed server certificate is not an identity, whatever fingerprint it
// carries.
//
// This test used to assert the opposite — "pinned self-signed server accepted" —
// which was right while the identity WAS a key. Under 2.0 the identity is the
// root, a lone certificate names no root, and the two ways to recognise a server
// are the chain validated to the pinned root (PACT §2) and WebPKI for the
// hostname. A key fingerprint is neither, so both halves of the old test now
// refuse: the "correct" pin and the wrong one are the same thing to a 2.0 caller,
// and that is the point.
func TestASelfSignedServerCertificateIsNotAnIdentity(t *testing.T) {
	srvKP, _ := identity.Generate(identity.AlgoP256)
	srvDER, _ := identity.SelfSignedCert(srvKP, "peer")
	got := make(chan []*x509.Certificate, 4)
	addr := startTLS(t, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKP.Signer}},
	}, got)
	c := accountClient(t)

	// The server's own key as the pin: refused. There is no chain to validate and
	// the certificate is not publicly trusted.
	its := Peer{Endpoint: "https://" + addr, Fingerprint: srvKP.Fingerprint}
	if conn, err := tls.Dial("tcp", addr, c.tlsConfig(its, "127.0.0.1")); err == nil {
		conn.Close()
		t.Fatal("a key-pinned self-signed server was accepted: the identity is the root (PACT §2)")
	}

	// Another key as the pin: refused for the same reason, by the same words. A
	// caller learns nothing from the difference, because there is none.
	other, _ := identity.Generate(identity.AlgoP256)
	if conn, err := tls.Dial("tcp", addr, c.tlsConfig(Peer{Endpoint: "https://" + addr, Fingerprint: other.Fingerprint}, "127.0.0.1")); err == nil {
		conn.Close()
		t.Fatal("wrong pin accepted - impersonation possible")
	}
}
func TestWebPKIPathWithInjectedRoots(t *testing.T) {
	// CA-signed server cert for "pact.example"; client trusts the CA via Roots.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "TestRoot"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "pact.example"},
		DNSNames:  []string{"pact.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)

	got := make(chan []*x509.Certificate, 4)
	addr := startTLS(t, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}},
	}, got)

	c := accountClient(t)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	c.Roots = roots

	// contact pinned some unrelated identity key; server presents WebPKI cert for
	// the right hostname → accepted under rule (a)-else-(b) of PACT §2
	someKP, _ := identity.Generate(identity.AlgoP256)
	peer := Peer{Endpoint: "https://pact.example/mcp", Fingerprint: someKP.Fingerprint}
	conn, err := tls.Dial("tcp", addr, c.tlsConfig(peer, "pact.example"))
	if err != nil {
		t.Fatalf("WebPKI-valid server rejected: %v", err)
	}
	conn.Close()
	<-got

	// wrong hostname must fail
	if conn, err := tls.Dial("tcp", addr, c.tlsConfig(peer, "evil.example")); err == nil {
		conn.Close()
		t.Fatal("hostname mismatch accepted")
	}
}

func TestPlaintextRefusedToSealRequiredPeer(t *testing.T) {
	c := accountClient(t)
	peer := Peer{Endpoint: "https://x", Fingerprint: "sha256:x", Seal: "required"}
	_, err := c.CallTool(t.Context(), peer, "send_message", map[string]any{}, CallOptions{Plaintext: true})
	if err == nil || !strings.Contains(err.Error(), "seal_required") {
		t.Fatalf("plaintext to required peer not refused locally: %v", err)
	}
	var httpUsed bool
	_ = httpUsed
	_ = http.DefaultClient
	if !errors.Is(err, ErrSealRequired) {
		t.Fatalf("sentinel: %v", err)
	}
}

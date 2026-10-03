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
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
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
	server := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
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

// A self-signed server certificate is not an identity, whoever the caller thinks it is dialling.
//
// This test used to assert the opposite — "pinned self-signed server accepted" — which was
// right while the identity WAS a key. Under 2.0 the identity is the root, a lone certificate
// names no root, and the two ways to recognise a server are the chain validated to the pinned
// root (HDTP §2) and WebPKI for the hostname. A lone certificate is neither — to a caller that
// holds a pin for this address and to a caller that holds none, in the same words, because a
// caller learns nothing from a difference there is no reason to have.
func TestASelfSignedServerCertificateIsNotAnIdentity(t *testing.T) {
	srvKP, _ := identity.Generate(identity.AlgoP256)
	srvDER, _ := identity.SelfSignedCert(srvKP, "peer")
	got := make(chan []*x509.Certificate, 4)
	addr := startTLS(t, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKP.Signer}},
	}, got)
	c := accountClient(t)

	refusal := func(peer Peer) string {
		t.Helper()
		conn, err := tls.Dial("tcp", addr, c.tlsConfig(peer, "127.0.0.1"))
		if err == nil {
			conn.Close()
			t.Fatal("a lone self-signed server certificate was accepted: the identity is the root (HDTP §2)")
		}
		return err.Error()
	}
	// A caller that pins a real identity at this address: the server is not it.
	pinned := newTestIdentity(t, "Bharat", "https://"+addr+"/mcp").peerOf()
	// A caller that holds no pin at all.
	unpinned := Peer{Endpoint: "https://" + addr}
	if a, b := refusal(pinned), refusal(unpinned); a != b {
		t.Fatalf("the refusal differs with what the caller holds, and need not:\n  pinned:   %s\n  unpinned: %s", a, b)
	}
}

func TestWebPKIPathWithInjectedRoots(t *testing.T) {
	// CA-signed server cert for "hdtp.example"; client trusts the CA via Roots.
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
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "hdtp.example"},
		DNSNames:  []string{"hdtp.example"},
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

	// The server presents a WebPKI certificate for the right hostname — what a terminating
	// edge presents — and is accepted on that: rule (a)-else-(b) of HDTP §2. Whose agent is
	// behind the edge is then the envelope's business, not TLS's.
	peer := Peer{Endpoint: "https://hdtp.example/mcp"}
	conn, err := tls.Dial("tcp", addr, c.tlsConfig(peer, "hdtp.example"))
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
	peer := Peer{Endpoint: "https://x", Seal: "required"}
	_, err := c.CallTool(t.Context(), peer, "send_message", map[string]any{}, CallOptions{Plaintext: true})
	if err == nil || !strings.Contains(err.Error(), "seal_required") {
		t.Fatalf("plaintext to required peer not refused locally: %v", err)
	}
	if !errors.Is(err, ErrSealRequired) {
		t.Fatalf("sentinel: %v", err)
	}
}

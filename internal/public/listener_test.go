package public

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// testServer starts a real TLS listener with two SNI accounts and an echo handler
// that returns the extracted TransportFacts + route vars as JSON.
func testServer(t *testing.T, slugs []string) (addr string, certs map[string]*tls.Certificate, stop func()) {
	t.Helper()
	certs = map[string]*tls.Certificate{}
	sniCerts := map[string]*tls.Certificate{}
	for _, slug := range slugs {
		kp, err := identity.Generate(identity.AlgoP256)
		if err != nil {
			t.Fatal(err)
		}
		der, err := identity.SelfSignedCert(kp, slug)
		if err != nil {
			t.Fatal(err)
		}
		c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
		certs[slug] = c
		sniCerts[slug+".example"] = c
	}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := FactsFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account": r.PathValue("slug"),
			"caller":  f.ClientCertFingerprint,
			"path":    r.URL.Path,
		})
	})
	srv := &Server{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := sniCerts[hello.ServerName]; ok {
				return c, nil
			}
			return certs[slugs[0]], nil
		},
		Accounts: func() []string { return slugs },
		MCP:      echo,
		Invite: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			io.WriteString(w, "invite:"+r.PathValue("token"))
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The node builds its own http.Server (internal/node), so this test does the
	// same rather than relying on a convenience wrapper nothing shipped used.
	hs := &http.Server{Handler: srv.Handler(), TLSConfig: srv.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	return ln.Addr().String(), certs, func() { ln.Close() }
}

func get(t *testing.T, addr, sni, path string, clientCert *tls.Certificate) (int, string, *x509.Certificate) {
	t.Helper()
	conf := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	if clientCert != nil {
		conf.Certificates = []tls.Certificate{*clientCert}
		// PACT §10: always send our cert regardless of the server's CA list.
		conf.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		}
	}
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	serverCert := conn.ConnectionState().PeerCertificates[0]
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, sni)
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), serverCert
}

func TestHandshakeAcceptsNoCertUnknownCertKnownCert(t *testing.T) {
	addr, certs, stop := testServer(t, []string{"work"})
	defer stop()

	// no client cert
	code, body, _ := get(t, addr, "work.example", "/a/work/mcp", nil)
	if code != 200 {
		t.Fatalf("no-cert: %d", code)
	}
	var f1 map[string]any
	_ = json.Unmarshal([]byte(body), &f1)
	if f1["caller"] != "" {
		t.Fatalf("no-cert caller should be empty, got %v", f1["caller"])
	}

	// unknown (fresh) client cert — must still handshake (guest tier, PACT §2)
	kp, _ := identity.Generate(identity.AlgoP256)
	der, _ := identity.SelfSignedCert(kp, "stranger")
	cc := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: kp.Signer}
	code, body, _ = get(t, addr, "work.example", "/a/work/mcp", cc)
	if code != 200 {
		t.Fatalf("unknown-cert: %d", code)
	}
	_ = json.Unmarshal([]byte(body), &f1)
	if f1["caller"] != kp.Fingerprint {
		t.Fatalf("caller fpr = %v, want %s", f1["caller"], kp.Fingerprint)
	}
	_ = certs
}

func TestSNISelectsPerAccountCert(t *testing.T) {
	addr, certs, stop := testServer(t, []string{"work", "home"})
	defer stop()
	_, _, sw := get(t, addr, "work.example", "/a/work/mcp", nil)
	_, _, sh := get(t, addr, "home.example", "/a/home/mcp", nil)
	wantW, _ := identity.Fingerprint(certs["work"].PrivateKey.(crypto.Signer).Public())
	wantH, _ := identity.Fingerprint(certs["home"].PrivateKey.(crypto.Signer).Public())
	gotW, _ := identity.Fingerprint(sw.PublicKey)
	gotH, _ := identity.Fingerprint(sh.PublicKey)
	if gotW != wantW || gotH != wantH || gotW == gotH {
		t.Fatalf("SNI cert selection wrong: %s/%s vs %s/%s", gotW, gotH, wantW, wantH)
	}
}

func TestRouting(t *testing.T) {
	addr, _, stop := testServer(t, []string{"work"})
	defer stop()
	if code, body, _ := get(t, addr, "work.example", "/mcp", nil); code != 200 {
		t.Fatalf("single-account /mcp alias: %d %s", code, body)
	}
	if code, body, _ := get(t, addr, "work.example", "/i/tok123", nil); code != 200 || body != "invite:tok123" {
		t.Fatalf("invite route: %d %q", code, body)
	}
	if code, _, _ := get(t, addr, "work.example", "/nope", nil); code != 404 {
		t.Fatal("wrong path should 404")
	}
	if code, _, _ := get(t, addr, "work.example", "/a/ghost/mcp", nil); code != 404 {
		t.Fatal("unknown slug should 404")
	}
}

func TestMCPAliasGoneWithTwoAccounts(t *testing.T) {
	addr, _, stop := testServer(t, []string{"work", "home"})
	defer stop()
	if code, _, _ := get(t, addr, "work.example", "/mcp", nil); code != 404 {
		t.Fatalf("/mcp with two accounts must 404, got %d", code)
	}
}

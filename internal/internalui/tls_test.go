package internalui

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/testid"
)

// freeAddr is a loopback address nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// serve runs Serve with a /healthz handler until the test ends, and waits until it accepts.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	go func() { done <- Serve(ctx, addr, cfg, mux) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("Serve never listened on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A configuration that names a certificate is served over TLS with it, and a plain HTTP request
// is not answered as one. Until 2026-09-27 Serve had no TLS path at all: the internal surface
// spoke plain HTTP on every bind the config accepted as "TLS".
func TestTheInternalSurfaceIsServedOverTheConfiguredTLS(t *testing.T) {
	certFile, keyFile, cert := testid.ServerFiles(t, t.TempDir(), "portal", "localhost")
	cfg, err := LoadTLS(certFile, keyFile)
	if err != nil || cfg == nil {
		t.Fatalf("LoadTLS: %v, %v", cfg, err)
	}
	addr := serve(t, cfg)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	secure := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	res, err := secure.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("a TLS client trusting the configured certificate could not reach the surface: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 200 || string(body) != "ok\n" {
		t.Fatalf("over TLS: %d %q", res.StatusCode, body)
	}
	if res.TLS == nil || !res.TLS.PeerCertificates[0].Equal(cert) {
		t.Fatal("the surface did not present the configured certificate")
	}

	plain := &http.Client{Timeout: 5 * time.Second}
	res, err = plain.Get("http://" + addr + "/healthz")
	if err == nil {
		body, _ = io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode == 200 || strings.Contains(string(body), "ok") {
			t.Fatalf("a plaintext request was answered as one: %d %q", res.StatusCode, body)
		}
	}
}

func TestWithNoCertificateTheSurfaceIsPlainHTTP(t *testing.T) {
	cfg, err := LoadTLS("", "")
	if err != nil || cfg != nil {
		t.Fatalf("no files gave %v, %v; want nil, nil", cfg, err)
	}
	addr := serve(t, nil)
	res, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("plain: %d", res.StatusCode)
	}
}

// A configuration that promises TLS and cannot keep it is refused, naming what it could not use.
func TestATLSConfigurationThatDoesNotLoadIsRefusedByName(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := testid.ServerFiles(t, dir, "portal", "localhost")
	_, otherKey, _ := testid.ServerFiles(t, dir, "other", "localhost")
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, cert, key, want string }{
		{"a certificate and no key", certFile, "", certFile},
		{"a key and no certificate", "", keyFile, keyFile},
		{"a certificate that is not one", garbage, keyFile, garbage},
		{"a key that does not match", certFile, otherKey, otherKey},
		{"a file that is not there", filepath.Join(dir, "absent.crt"), keyFile, "absent.crt"},
	} {
		cfg, err := LoadTLS(c.cert, c.key)
		if err == nil || cfg != nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, %v; want a refusal naming %s", c.name, cfg, err, c.want)
		}
	}
}

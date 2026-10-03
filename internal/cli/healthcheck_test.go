package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// With internal TLS configured, serve's portal speaks TLS, a plaintext request is not answered as
// one, and the healthcheck — what the container HEALTHCHECK and the harness wait on — reaches it.
// Both ends of one change: the healthcheck used to dial http:// whatever the config said, so it
// would have gone red the day the listener honoured the certificate.
func TestServeHonoursInternalTLSAndTheHealthcheckFollowsIt(t *testing.T) {
	certFile, keyFile, _ := testid.ServerFiles(t, t.TempDir(), "portal", "localhost")
	r := runServeWith(t, map[string]any{"internal_tls_cert": certFile, "internal_tls_key": keyFile}, nil)

	res, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + r.internal + "/healthz")
	if err == nil {
		_ = res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Fatal("serve answered a plaintext /healthz with 200 while configured for TLS")
		}
	}
	var stderr bytes.Buffer
	if code := healthcheck([]string{"--config", filepath.Join(r.dir, "config.json")}, &stderr); code != 0 {
		t.Fatalf("the healthcheck of a TLS portal exited %d: %s", code, stderr.String())
	}
}

func TestTheHealthcheckOfAPlainPortal(t *testing.T) {
	r := runServe(t, nil)
	var stderr bytes.Buffer
	if code := healthcheck([]string{"--config", filepath.Join(r.dir, "config.json")}, &stderr); code != 0 {
		t.Fatalf("the healthcheck of a plain portal exited %d: %s", code, stderr.String())
	}
}

// The healthcheck accepts the configured certificate and no other: a listener presenting a
// different one is not the node's own.
func TestTheHealthcheckAcceptsOnlyTheConfiguredCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := testid.ServerFiles(t, dir, "portal", "localhost")
	otherCert, otherKey, _ := testid.ServerFiles(t, dir, "other", "localhost")
	served, err := internalui.LoadTLS(otherCert, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	go func() { done <- internalui.Serve(ctx, addr, served, mux) }()
	t.Cleanup(func() { cancel(); <-done })

	client, url, err := healthClient(&core.Config{InternalBind: addr, InternalTLSCert: certFile, InternalTLSKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, "https://") {
		t.Fatalf("with internal TLS configured the healthcheck dials %s", url)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := client.Get(url)
		if err != nil && strings.Contains(err.Error(), "other than internal_tls_cert") {
			return
		}
		if err == nil {
			_ = res.Body.Close()
			t.Fatalf("a listener presenting another certificate was taken for the node's own (%d)", res.StatusCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("never refused on the certificate: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// serve refuses to start when its TLS files do not load, before it opens anything, and says which.
func TestServeRefusesATLSConfigurationThatDoesNotLoad(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.crt")
	_, keyFile, _ := testid.ServerFiles(t, dir, "portal", "localhost")
	cfg := map[string]any{
		"data_dir": filepath.Join(dir, "data"), "internal_bind": freePort(t), "public_bind": freePort(t),
		"public_url": "https://127.0.0.1:1", "store_engine": "sqlite",
		"internal_tls_cert": missing, "internal_tls_key": keyFile,
	}
	b, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := serveWith(context.Background(), []string{"--config", cfgPath}, &out, &out)
	if code == 0 || !strings.Contains(out.String(), missing) {
		t.Fatalf("serve with an unloadable certificate exited %d: %s", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Errorf("serve created its data directory before refusing its TLS configuration (%v)", err)
	}
}

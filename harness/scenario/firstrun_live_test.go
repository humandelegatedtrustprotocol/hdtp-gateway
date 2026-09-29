package scenario

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/portal"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

// S1 — first run, from a pristine image: the node prints where to go and the setup token, the
// token admits the wizard and is NOT burned by the wizard's first requests, a passkey is
// registered in a real browser, the dashboard draws, the passkey signs the owner in again from the
// sign-in page once the session is gone, and the wizard is gone.
//
// Every other scenario reaches the portal through the loopback sidecar (World.Bridge), as the
// README's quickstart does, and on loopback the wizard needs no token at all (SPEC §8.6), so none
// of them says anything about the token. This node binds its owner surface to every interface,
// which SPEC §8.3 allows only with passkey auth, TLS and a named host: so it is served over TLS
// for `localhost` with a certificate made here, and the browser is told to trust that one key.
// A request published through Docker arrives from Docker's gateway, not from loopback, so here the
// token is the only way in. Until 2026-09-27 this node could not be written: the configured
// certificate was never loaded, and the portal spoke plaintext on every interface.
//
// The ceremony is the proof that the token survives first use: rendering the wizard, beginning
// the ceremony and finishing it are three requests, each checked against the token, and it is
// consumed only once a passkey exists.
func TestFirstRunFromAPristineImage(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S1", Name: "first run: the setup token admits the wizard, survives its first requests, and dies with the first passkey", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 8 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir, spki, pool := selfSignedCertificate(t, "localhost")
	port, err := fabric.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	env := topology.NodeEnv(fmt.Sprintf("https://%s:%d", w.Fab.Name("first"), topology.PublicPort))
	maps.Copy(env, map[string]string{
		"PACT_INTERNAL_BIND":         fmt.Sprintf("0.0.0.0:%d", topology.InternalPort),
		"PACT_INTERNAL_HOST":         "localhost",
		"PACT_INTERNAL_AUTH_ENABLED": "true",
		"PACT_INTERNAL_TLS_CERT":     "/tls/cert.pem",
		"PACT_INTERNAL_TLS_KEY":      "/tls/key.pem",
	})
	node, err := topology.Serve(ctx, w.Fab, fabric.Spec{
		Name: "first", Image: images.Node, Network: net, Env: env, Cmd: []string{"serve"},
		Ports:   []string{fmt.Sprintf("%s:%d", port, topology.InternalPort)},
		Volumes: []string{dir + ":/tls:ro"},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "https://localhost:" + port
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(path string) (int, string) {
		t.Helper()
		res, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return res.StatusCode, string(b)
	}

	// The node's own healthcheck says it is up. It reaches the portal the way serve serves it, so
	// on this node it speaks TLS and accepts only the configured certificate.
	if err := topology.WaitHealthy(ctx, w.Fab, node); err != nil {
		t.Fatal(err)
	}
	// And from off the machine the portal speaks TLS, and nothing else.
	if res, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://localhost:" + port + "/healthz"); err == nil {
		_ = res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Fatal("the portal configured for TLS answered a plaintext request")
		}
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Fatalf("GET /healthz over TLS answered %d", code)
	}

	// What an owner reads first: where the portal is, and the link that opens the wizard.
	logs, err := w.Fab.Raw(ctx, "docker", "logs", node.Name)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`setup:\s+(https://localhost:\d+/setup\?token=([0-9a-f]+))`).FindStringSubmatch(string(logs))
	if m == nil {
		t.Fatalf("a first run printed no https setup link for its named host:\n%s", shorten(string(logs), 1200))
	}
	token := m[2]
	if !strings.Contains(string(logs), "valid until a passkey is registered") {
		t.Errorf("the setup link is printed without saying how long it lives:\n%s", shorten(string(logs), 1200))
	}

	// The token is what admits the wizard here, and looking at the wizard does not spend it.
	if code, _ := get("/setup"); code != http.StatusForbidden {
		t.Fatalf("GET /setup with no token from off the machine answered %d, want 403", code)
	}
	if code, _ := get("/setup?token=" + strings.Repeat("0", len(token))); code != http.StatusForbidden {
		t.Errorf("a wrong token answered %d, want 403", code)
	}
	for i := 1; i <= 2; i++ {
		if code, _ := get("/setup?token=" + token); code != http.StatusOK {
			t.Fatalf("opening the wizard with the token, time %d, answered %d: the token was spent by looking", i, code)
		}
	}

	// The ceremony, in a browser that trusts this one key and nothing else.
	br, err := portal.OpenTrusting(ctx, spki)
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	defer br.Close()
	msg, err := br.RegisterFirstPasskey(ctx, base+"/setup?token="+token, "first")
	if err != nil {
		t.Fatalf("the wizard, over TLS with the token: %v (page said %q)", err, msg)
	}
	out, _ := w.Fab.Exec(ctx, node, "/pact-gateway", "passkey", "list")
	if n := strings.Count(string(out), "owner="); n != 1 {
		t.Fatalf("after the ceremony the node lists %d passkeys, want 1:\n%s", n, out)
	}

	// Signed in: the dashboard draws, with a way to go somewhere.
	home, err := br.Rendered(ctx, base+"/")
	if err != nil {
		t.Fatalf("the dashboard: %v", err)
	}
	if !home.HasNav || len(home.Links) == 0 {
		t.Errorf("the dashboard drew no navigation: %q", shorten(home.Text, 300))
	}

	// And the passkey signs its owner in again once the session is gone. The sign-in page asks for
	// a discoverable credential (no list), so a passkey registered without one registers, signs in
	// once through the wizard's own session, and is never offered again — found 2026-09-28, when a
	// changed public URL renamed the session cookie and the owner could not get back in.
	if msg, err := br.SignInWithPasskey(ctx, base); err != nil {
		t.Fatalf("signing in again with the passkey the wizard registered: %v (page said %q)", err, msg)
	}
	if again, err := br.Rendered(ctx, base+"/"); err != nil || !again.HasNav {
		t.Fatalf("after signing in with the passkey, the dashboard did not draw: %v %q", err, shorten(again.Text, 300))
	}

	// And the wizard is gone: the first-run token died with the first passkey.
	if code, _ := get("/setup?token=" + token); code != http.StatusNotFound {
		t.Errorf("after the first passkey, the first-run token still reaches the wizard (%d, want 404)", code)
	}
}

// selfSignedCertificate makes a self-signed certificate for the DNS name `name` in a directory a
// container can mount, and returns the directory, the base64 SHA-256 of its public key (what
// Chrome is told to trust) and a pool holding it (what this process trusts).
func selfSignedCertificate(t *testing.T, name string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// The container runs as an unprivileged user and must read both files through the mount.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"cert.pem": {Type: "CERTIFICATE", Bytes: der},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return dir, base64.StdEncoding.EncodeToString(sum[:]), pool
}

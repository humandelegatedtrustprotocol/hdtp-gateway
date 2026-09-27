package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core"
)

func TestEdgeAdaptersDeriveEdgeMode(t *testing.T) {
	for _, name := range []string{"cloudflare", "ngrok-https"} {
		edge, err := derivesEdge(t, name)
		if err != nil || !edge {
			t.Fatalf("%s must terminate at an edge: %v %v", name, edge, err)
		}
		// config resolution FORCES the knobs, whatever the owner wrote
		dir := t.TempDir()
		c, err := core.Load("", func(k string) (string, bool) {
			v, ok := map[string]string{
				"PACT_DATA_DIR": dir, "PACT_TUNNEL": name,
				"PACT_MODE": "direct", "PACT_SEAL": "none", "PACT_CLIENT_CERT": "required",
			}[k]
			return v, ok
		})
		if err != nil {
			t.Fatal(err)
		}
		if c.Mode != core.ModeEdge || c.Seal != core.SealRequired || c.ClientCert != core.ClientCertOff {
			t.Fatalf("%s derived %s/%s/%s", name, c.Mode, c.Seal, c.ClientCert)
		}
		if c.LANConnections {
			t.Fatalf("%s: LAN flag must default OFF in edge mode", name)
		}
	}
}

func TestCloudflareOptionsAndSidecarFallback(t *testing.T) {
	t.Setenv("TUNNEL_TOKEN", "")
	if _, err := cloudflareOptions(Options{}); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("token not required: %v", err)
	}
	if _, err := cloudflareOptions(Options{Extra: map[string]string{"token": "t"}}); err == nil || !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("hostname not required: %v", err)
	}
	// env fallback for the token
	t.Setenv("TUNNEL_TOKEN", "envtok")
	o, err := cloudflareOptions(Options{Extra: map[string]string{"hostname": "pact.example.com"}})
	if err != nil || o.Token != "envtok" {
		t.Fatalf("%+v %v", o, err)
	}
	// sidecar mode: no child is spawned, the adapter still reports its URL
	a, err := New("cloudflare", Options{Extra: map[string]string{
		"token": "t", "hostname": "pact.example.com", "sidecar": "true",
	}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.Start(context.Background())
	if err != nil || !info.TerminatesAtEdge || info.PublicURL != "https://pact.example.com" {
		t.Fatalf("info: %+v %v", info, err)
	}
	if st := a.Status(); !st.Running || !strings.Contains(st.Detail, "sidecar") {
		t.Fatalf("status: %+v", st)
	}
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	// the printed snippet is runnable compose
	snip := ComposeSidecar("t")
	for _, want := range []string{"cloudflare/cloudflared", "tunnel --no-autoupdate run", "TUNNEL_TOKEN"} {
		if !strings.Contains(snip, want) {
			t.Fatalf("sidecar snippet missing %q:\n%s", want, snip)
		}
	}
}

func TestCloudflareSpawnsTheConnector(t *testing.T) {
	var gotToken string
	cf := &Cloudflare{
		opts: cloudflareOpts{Token: "tok", Hostname: "pact.example.com", Binary: "/bin/echo"},
		spawn: func(ctx context.Context, bin, token string) (*exec.Cmd, error) {
			gotToken = token
			cmd := exec.CommandContext(ctx, "/bin/echo", "connector")
			return cmd, cmd.Start()
		},
	}
	if _, err := cf.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotToken != "tok" {
		t.Fatalf("token not handed to the connector: %q", gotToken)
	}
	if st := cf.Status(); !st.Running || !strings.Contains(st.Detail, "edge mode") {
		t.Fatalf("status: %+v", st)
	}
	_ = cf.Stop()
	if cf.Status().Running {
		t.Fatal("still running after Stop")
	}
}

func TestNgrokHTTPSIsEdgeAndRefusesTLSURL(t *testing.T) {
	t.Setenv("NGROK_AUTHTOKEN", "")
	if _, err := ngrokHTTPSOptions(Options{}); err == nil {
		t.Fatal("token not required")
	}
	if _, err := ngrokHTTPSOptions(Options{Extra: map[string]string{"auth_token": "t", "url": "tls://x"}}); err == nil {
		t.Fatal("tls:// accepted by the https adapter")
	}
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &NgrokHTTPS{opts: ngrokHTTPSOpts{AuthToken: "t", URL: "https://", Name: "pact"},
		listen: func(context.Context, ngrokHTTPSOpts) (net.Listener, string, error) {
			return local, "https://pact.ngrok.app", nil
		}}
	info, err := a.Start(context.Background())
	if err != nil || !info.TerminatesAtEdge || info.Listener == nil || info.PublicURL != "https://pact.ngrok.app" {
		t.Fatalf("info: %+v %v", info, err)
	}
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
}

// SPEC §5.7: only the adapter's own trusted header may supply the source IP,
// and only on an edge listener; X-Forwarded-For is never honored.
func TestSourceIPHonorsOnlyTheAdaptersTrustedHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/a/me/mcp", nil)
	r.RemoteAddr = "10.0.0.9:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")

	if got := SourceIP("cloudflare", true, r); got != "198.51.100.7" {
		t.Fatalf("edge source: %s", got)
	}
	// a direct adapter ignores headers entirely, even Cloudflare's
	if got := SourceIP("direct", false, r); got != "10.0.0.9" {
		t.Fatalf("direct source: %s", got)
	}
	// an edge adapter with no trusted header falls back to the socket
	if got := SourceIP("ngrok-https", true, r); got != "10.0.0.9" {
		t.Fatalf("headerless edge: %s", got)
	}
	if TrustedClientIPHeader("tailscale") != "" || TrustedClientIPHeader("cloudflare") != "CF-Connecting-IP" {
		t.Fatal("trusted header table")
	}
	// and X-Forwarded-For is never the answer
	for _, adapter := range []string{"direct", "cloudflare", "ngrok-https", "frp"} {
		if SourceIP(adapter, true, r) == "203.0.113.9" {
			t.Fatalf("%s honored X-Forwarded-For", adapter)
		}
	}
}

var _ = io.Discard
var _ = http.StatusOK

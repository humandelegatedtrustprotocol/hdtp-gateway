package tunnel

import (
	"context"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

func TestEdgeAdaptersDeriveEdgeMode(t *testing.T) {
	for _, name := range []string{"cloudflare", "edge"} {
		edge, err := derivesEdge(t, name)
		if err != nil || !edge {
			t.Fatalf("%s must terminate at an edge: %v %v", name, edge, err)
		}
		// config resolution FORCES the knobs, whatever the owner wrote
		dir := t.TempDir()
		c, err := core.Load("", func(k string) (string, bool) {
			v, ok := map[string]string{
				"HDTP_DATA_DIR": dir, "HDTP_TUNNEL": name,
				"HDTP_SEAL": "none", "HDTP_CLIENT_CERT": "required",
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

// ngrok-https is gone (#167): it wrapped ngrok's decrypted-HTTP listener in the node's TLS and
// served nothing. A node that still names it refuses to start, saying so, rather than serving
// nothing; ngrok's agent as a sidecar is the `edge` adapter.
func TestNgrokHTTPSIsNotAnAdapter(t *testing.T) {
	if _, err := derivesEdge(t, "ngrok-https"); err == nil || !strings.Contains(err.Error(), `tunnel "ngrok-https" is not a registered adapter`) {
		t.Fatalf("ngrok-https still resolves: %v", err)
	}
	if _, err := New("ngrok-https", Options{}); err == nil {
		t.Fatal("ngrok-https still constructs")
	}
	// A stored selection of it stops the node before the portal serves; HDTP_TUNNEL wins over
	// the store, so setting it in the environment is the way back in.
	stored := map[string]string{"tunnel": "ngrok-https"}
	for _, env := range []map[string]string{{}, {"HDTP_TUNNEL": "edge"}} {
		env["HDTP_DATA_DIR"] = t.TempDir()
		c, err := core.Load("", func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if err != nil {
			t.Fatal(err)
		}
		err = c.ApplyStoreSettings(stored)
		if _, pinned := env["HDTP_TUNNEL"]; pinned {
			if err != nil || c.Tunnel != "edge" || c.Mode != core.ModeEdge {
				t.Fatalf("HDTP_TUNNEL=edge over a stored ngrok-https: tunnel %q mode %s, %v", c.Tunnel, c.Mode, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), `tunnel "ngrok-https" is not a registered adapter`) {
			t.Fatalf("a stored ngrok-https was accepted: %v", err)
		}
	}
}

func TestCloudflareOptionsAndSidecarFallback(t *testing.T) {
	t.Setenv("TUNNEL_TOKEN", "")
	if _, err := cloudflareOptions(Options{Extra: map[string]string{"token": "t"}}); err == nil || !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("hostname not required: %v", err)
	}
	// the token is the connector's: with the sidecar running it, the node needs none (#168)
	side, err := New("cloudflare", Options{Extra: map[string]string{"hostname": "hdtp.example.com", "sidecar": "true"}})
	if err != nil {
		t.Fatalf("sidecar without a token refused: %v", err)
	}
	if info, err := side.Start(context.Background()); err != nil || info.PublicURL != "https://hdtp.example.com" || !side.Status().Running {
		t.Fatalf("sidecar without a token: %+v %v", info, err)
	}
	// spawning the connector does need it, and nothing is spawned without it
	spawned := false
	noTok := &Cloudflare{opts: cloudflareOpts{Hostname: "hdtp.example.com", Binary: "/bin/echo"},
		spawn: func(context.Context, string, string) (*exec.Cmd, error) { spawned = true; return nil, nil }}
	if _, err := noTok.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "token") || spawned {
		t.Fatalf("spawn without a token: err %v, spawned %v", err, spawned)
	}
	// env fallback for the token
	t.Setenv("TUNNEL_TOKEN", "envtok")
	o, err := cloudflareOptions(Options{Extra: map[string]string{"hostname": "hdtp.example.com"}})
	if err != nil || o.Token != "envtok" {
		t.Fatalf("%+v %v", o, err)
	}
	// sidecar mode: no child is spawned, the adapter still reports its URL
	a, err := New("cloudflare", Options{Extra: map[string]string{
		"token": "t", "hostname": "hdtp.example.com", "sidecar": "true",
	}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.Start(context.Background())
	if err != nil || !info.TerminatesAtEdge || info.PublicURL != "https://hdtp.example.com" {
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
		opts: cloudflareOpts{Token: "tok", Hostname: "hdtp.example.com", Binary: "/bin/echo"},
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

// The generic edge adapter: a sidecar terminates TLS, so the node starts nothing, advertises the
// owner's public URL (none yet is not a failure: the portal sets it), and takes the source address
// from the socket whatever header the sidecar or a caller sets.
func TestEdgeAdapterStartsNothingAndTrustsNoHeader(t *testing.T) {
	for _, url := range []string{"https://n.ngrok-free.dev", ""} {
		a, err := New("edge", Options{PublicURL: url, PublicBind: "127.0.0.1:8443"})
		if err != nil {
			t.Fatal(err)
		}
		info, err := a.Start(context.Background())
		if err != nil || !info.TerminatesAtEdge || info.Listener != nil || info.PublicURL != url {
			t.Fatalf("info: %+v %v", info, err)
		}
		if st := a.Status(); st.Name != "edge" || !st.Running || st.PublicURL != url || !strings.Contains(st.Detail, "sidecar terminates TLS") {
			t.Fatalf("status: %+v", st)
		}
		if err := a.Stop(); err != nil || a.Status().Running {
			t.Fatalf("stop: %v %+v", err, a.Status())
		}
	}
	r := httptest.NewRequest("POST", "/a/me/mcp", nil)
	r.RemoteAddr = "172.18.0.4:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if got := SourceIP("edge", true, r); got != "172.18.0.4" {
		t.Fatalf("edge source: %s", got)
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
	if got := SourceIP("edge", true, r); got != "10.0.0.9" {
		t.Fatalf("headerless edge: %s", got)
	}
	if TrustedClientIPHeader("tailscale") != "" || TrustedClientIPHeader("cloudflare") != "CF-Connecting-IP" {
		t.Fatal("trusted header table")
	}
	// and X-Forwarded-For is never the answer
	for _, adapter := range []string{"direct", "cloudflare", "edge", "frp"} {
		if SourceIP(adapter, true, r) == "203.0.113.9" {
			t.Fatalf("%s honored X-Forwarded-For", adapter)
		}
	}
}

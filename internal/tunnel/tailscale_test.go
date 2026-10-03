package tunnel

import (
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// Funnel itself cannot run in the automated gate (needs a tailnet + auth key): these cover the
// configuration plumbing; the live run is documented in docs/demos/tailscale-funnel.md.
func TestTailscaleOptionsPlumbing(t *testing.T) {
	t.Setenv("TS_AUTHKEY", "")
	if _, err := tailscaleOptions(Options{}); err == nil || !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("hostname not required: %v", err)
	}
	if _, err := tailscaleOptions(Options{Extra: map[string]string{"hostname": "hdtp"}}); err == nil || !strings.Contains(err.Error(), "auth_key") {
		t.Fatalf("auth key not required: %v", err)
	}
	// env fallback for the key, default port 443
	t.Setenv("TS_AUTHKEY", "tskey-auth-x")
	o, err := tailscaleOptions(Options{Extra: map[string]string{"hostname": "hdtp"}})
	if err != nil || o.AuthKey != "tskey-auth-x" || o.Port != 443 || o.FunnelOnly {
		t.Fatalf("%+v %v", o, err)
	}
	// Funnel port limits (443/8443/10000 only)
	for _, p := range []string{"8443", "10000"} {
		if _, err := tailscaleOptions(Options{Extra: map[string]string{"hostname": "hdtp", "port": p}}); err != nil {
			t.Fatalf("port %s refused: %v", p, err)
		}
	}
	for _, p := range []string{"80", "8080", "abc"} {
		if _, err := tailscaleOptions(Options{Extra: map[string]string{"hostname": "hdtp", "port": p}}); err == nil {
			t.Fatalf("port %s accepted", p)
		}
	}
	o, _ = tailscaleOptions(Options{Extra: map[string]string{"hostname": "hdtp", "funnel_only": "true", "port": "8443"}})
	if !o.FunnelOnly || o.Port != 8443 {
		t.Fatalf("%+v", o)
	}
	if funnelURL("hdtp.tail1234.ts.net", 443) != "https://hdtp.tail1234.ts.net" ||
		funnelURL("hdtp.tail1234.ts.net", 8443) != "https://hdtp.tail1234.ts.net:8443" {
		t.Fatal("funnel url")
	}
}

func TestTailscaleIsRegisteredAsDirectMode(t *testing.T) {
	edge, err := derivesEdge(t, "tailscale")
	if err != nil || edge {
		t.Fatalf("tailscale must be a direct-mode adapter: edge=%v err=%v", edge, err)
	}
	// config resolution derives DIRECT mode for it (SPEC §10.1)
	dir := t.TempDir()
	c, err := core.Load("", func(k string) (string, bool) {
		v, ok := map[string]string{"HDTP_DATA_DIR": dir, "HDTP_TUNNEL": "tailscale"}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != core.ModeDirect || c.ClientCert != core.ClientCertPreferred {
		t.Fatalf("derived: mode=%s cc=%s", c.Mode, c.ClientCert)
	}
	t.Setenv("TS_AUTHKEY", "")
	if _, err := New("tailscale", Options{}); err == nil {
		t.Fatal("constructed without hostname/key")
	}
}

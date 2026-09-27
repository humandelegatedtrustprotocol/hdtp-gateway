package tunnel

import (
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core"
)

// The two ingress-fronted adapters derive opposite modes (SPEC §10.6):
// passthrough keeps end-to-end mTLS (direct), terminate hands the public TLS to
// the ingress (edge: seal forced required, client_cert forced off).
func TestIngressAdaptersDeriveModes(t *testing.T) {
	for name, wantEdge := range map[string]bool{"ingress-passthrough": false, "ingress-terminate": true} {
		edge, err := derivesEdge(t, name)
		if err != nil || edge != wantEdge {
			t.Fatalf("%s: edge=%v err=%v", name, edge, err)
		}
		dir := t.TempDir()
		c, err := core.Load("", func(k string) (string, bool) {
			v, ok := map[string]string{"PACT_DATA_DIR": dir, "PACT_TUNNEL": name, "PACT_SEAL": "optional"}[k]
			return v, ok
		})
		if err != nil {
			t.Fatal(err)
		}
		if wantEdge && (c.Mode != core.ModeEdge || c.Seal != core.SealRequired || c.ClientCert != core.ClientCertOff) {
			t.Fatalf("%s derived %s/%s/%s, want edge/required/off", name, c.Mode, c.Seal, c.ClientCert)
		}
		if !wantEdge && (c.Mode != core.ModeDirect || c.Seal != core.SealOptional) {
			t.Fatalf("%s derived %s/%s, want direct/optional", name, c.Mode, c.Seal)
		}
	}
	// pairing data is mandatory
	if _, err := New("ingress-terminate", Options{PublicBind: "127.0.0.1:1"}); err == nil {
		t.Fatal("constructed without pairing data")
	}
	a, err := New("ingress-terminate", Options{PublicBind: "127.0.0.1:8443", Extra: map[string]string{
		"subdomain": "beta", "domain": "example.test", "data_plane_addr": "127.0.0.1",
		"node_fpr": "sha256:x", "node_secret": "s",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if st := a.Status(); st.Name != "frp" || st.PublicURL != "https://beta.internal.example.test" {
		t.Fatalf("terminate adapter should tunnel the INTERNAL name: %+v", st)
	}
}

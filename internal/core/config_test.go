package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: load with a clean env, optional file content, and env overrides.
func load(t *testing.T, fileJSON string, env map[string]string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := ""
	if fileJSON != "" {
		path = filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(fileJSON), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	return Load(path, lookup)
}

func TestDefaults(t *testing.T) {
	c, err := load(t, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicBind != ":8443" || c.InternalBind != "127.0.0.1:8080" {
		t.Fatalf("default binds wrong: %q %q", c.PublicBind, c.InternalBind)
	}
	if c.Mode != ModeDirect || c.Seal != SealRequired || c.ClientCert != ClientCertPreferred {
		t.Fatalf("default knobs wrong: %v %v %v", c.Mode, c.Seal, c.ClientCert)
	}
	if c.StoreEngine != "sqlite" {
		t.Fatalf("default engine = %q", c.StoreEngine)
	}
	if !c.LANConnections { // direct mode default: on (SPEC §5.1/§10.1)
		t.Fatal("direct-mode LAN flag should default on")
	}
}

func TestPrecedenceEnvOverFileOverDefaults(t *testing.T) {
	c, err := load(t, `{"public_bind": ":9000", "seal": "optional"}`,
		map[string]string{"PACT_PUBLIC_BIND": ":9100"})
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicBind != ":9100" {
		t.Fatalf("env must beat file: got %q", c.PublicBind)
	}
	if c.Seal != SealOptional {
		t.Fatalf("file must beat default: got %v", c.Seal)
	}
	if c.InternalBind != "127.0.0.1:8080" {
		t.Fatalf("default must fill the rest: got %q", c.InternalBind)
	}
}

func TestRejections(t *testing.T) {
	cases := []struct {
		name string
		file string
		env  map[string]string
		rule string
	}{
		{"non-loopback internal without auth+tls", `{"internal_bind": "0.0.0.0:8080"}`, nil, RuleInternalBindAuth},
		{"non-loopback internal with auth but no tls", `{"internal_bind": "0.0.0.0:8080", "internal_auth_enabled": true}`, nil, RuleInternalBindAuth},
		{"empty-host internal bind is non-loopback", `{"internal_bind": ":8080"}`, nil, RuleInternalBindAuth},
		{"postgres without dsn", `{"store_engine": "postgres"}`, nil, RulePostgresDSN},
		{"edge with seal optional", `{"mode": "edge", "seal": "optional"}`, nil, RuleEdgeSeal},
		{"edge with client_cert preferred", `{"mode": "edge", "client_cert": "preferred"}`, nil, RuleEdgeClientCert},
		{"bad seal enum", `{"seal": "sometimes"}`, nil, RuleEnum},
		{"bad mode enum", `{"mode": "hybrid"}`, nil, RuleEnum},
		{"bad client_cert enum via env", ``, map[string]string{"PACT_CLIENT_CERT": "maybe"}, RuleEnum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.file, tc.env)
			if err == nil {
				t.Fatal("want rejection, got nil error")
			}
			if !strings.Contains(err.Error(), tc.rule) {
				t.Fatalf("error %q does not name rule %q", err, tc.rule)
			}
		})
	}
}

func TestValidNonLoopbackInternal(t *testing.T) {
	c, err := load(t, `{"internal_bind": "0.0.0.0:8080", "internal_auth_enabled": true,
		"internal_host": "pact.example.com",
		"internal_tls_cert": "/x/cert.pem", "internal_tls_key": "/x/key.pem"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.InternalBind != "0.0.0.0:8080" || c.InternalHost != "pact.example.com" {
		t.Fatalf("got %q / %q", c.InternalBind, c.InternalHost)
	}
}

// AC (P7-03a): a non-loopback portal with no internal_host would start cleanly
// and be impossible to log into — every WebAuthn ceremony would be refused,
// because the relying party is matched against an allow-list that would be
// empty. Refuse at startup instead.
func TestNonLoopbackInternalNeedsAHost(t *testing.T) {
	_, err := load(t, `{"internal_bind": "0.0.0.0:8080", "internal_auth_enabled": true,
		"internal_tls_cert": "/x/cert.pem", "internal_tls_key": "/x/key.pem"}`, nil)
	if err == nil {
		t.Fatal("a non-loopback portal was accepted with no internal_host")
	}
	if !strings.Contains(err.Error(), RuleInternalHost) {
		t.Fatalf("the error should name the rule: %v", err)
	}
}

func TestEdgeModeValidWhenForcedKnobsMatch(t *testing.T) {
	c, err := load(t, `{"mode": "edge", "seal": "required", "client_cert": "off"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LANConnections { // edge mode default: off (SPEC §2.5/§10.1)
		t.Fatal("edge-mode LAN flag should default off")
	}
}

func TestLANFlagExplicitOverride(t *testing.T) {
	c, err := load(t, `{"mode": "edge", "seal": "required", "client_cert": "off", "lan_connections": true}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.LANConnections {
		t.Fatal("explicit lan_connections must win over mode default")
	}
}

func TestLoopbackVariants(t *testing.T) {
	for _, bind := range []string{"127.0.0.1:1", "[::1]:1", "localhost:1", "127.9.9.9:1"} {
		if _, err := load(t, `{"internal_bind": "`+bind+`"}`, nil); err != nil {
			t.Fatalf("loopback bind %q wrongly rejected: %v", bind, err)
		}
	}
}

// SPEC §10.1: the mode is DERIVED from the adapter's TerminatesAtEdge flag, and
// an edge adapter forces seal=required + client_cert=off regardless of what the
// owner wrote.
func TestTunnelAdapterDerivesModeAndForcesEdgeKnobs(t *testing.T) {
	RegisterTunnel("fake-edge", true)
	RegisterTunnel("fake-direct", false)
	// edge adapter: owner asked for direct + relaxed knobs; derivation overrides
	c, err := load(t, "", map[string]string{
		"PACT_TUNNEL": "fake-edge",
		"PACT_MODE":   "direct", "PACT_SEAL": "optional", "PACT_CLIENT_CERT": "preferred",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeEdge || c.Seal != SealRequired || c.ClientCert != ClientCertOff || c.LANConnections {
		t.Fatalf("edge derivation: mode=%s seal=%s cc=%s lan=%v", c.Mode, c.Seal, c.ClientCert, c.LANConnections)
	}
	// direct adapter: direct mode, owner's relaxed seal honored
	c, err = load(t, "", map[string]string{"PACT_TUNNEL": "fake-direct", "PACT_SEAL": "optional"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDirect || c.Seal != SealOptional || c.ClientCert != ClientCertPreferred || !c.LANConnections {
		t.Fatalf("direct derivation: %+v", c)
	}
	// unknown adapter names are refused at resolution
	if _, err := load(t, "", map[string]string{"PACT_TUNNEL": "carrier-pigeon"}); err == nil {
		t.Fatal("unknown tunnel accepted")
	}
}


// PACT §12's caps are defaults, not a ceiling, so they are knobs — and a knob
// has to behave like every other one: settable from the portal, overridable by
// the file, and pinned by the environment above both (SPEC §12.2). A typo must
// restore the documented number rather than removing the budget.
func TestCallBudgetsAreOwnerSettableKnobs(t *testing.T) {
	c, err := load(t, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LimitContactPerHour != 0 || c.LimitGuestPerHour != 0 {
		t.Fatalf("unset should mean the documented default: %+v", c)
	}

	c, err = load(t, `{"limit_contact_per_hour": 200}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LimitContactPerHour != 200 {
		t.Errorf("file layer ignored: %d", c.LimitContactPerHour)
	}

	c, err = load(t, `{"limit_contact_per_hour": 200}`, map[string]string{
		"PACT_LIMIT_CONTACT_PER_HOUR": "500", "PACT_LIMIT_GUEST_PER_HOUR": "25",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.LimitContactPerHour != 500 || c.LimitGuestPerHour != 25 {
		t.Errorf("environment does not beat the file: %d/%d", c.LimitContactPerHour, c.LimitGuestPerHour)
	}
	if !c.EnvPinned["limit.contact_per_hour"] {
		t.Error("an environment-set budget is not reported as pinned, so the portal would offer to change it")
	}

	// A value nobody can read is not a licence to stop counting.
	c, err = load(t, "", map[string]string{"PACT_LIMIT_CONTACT_PER_HOUR": "lots"})
	if err != nil {
		t.Fatal(err)
	}
	if c.LimitContactPerHour != 0 {
		t.Errorf("an unreadable budget became %d instead of the default", c.LimitContactPerHour)
	}

	// And the portal's own validation refuses what it would have to ignore.
	if err := ValidateSetting("limit.guest_per_hour", "0"); err == nil {
		t.Error("zero was accepted; it would read as the default, not as no calls")
	}
	if err := ValidateSetting("limit.guest_per_hour", "25"); err != nil {
		t.Errorf("a plain number was refused: %v", err)
	}
	if err := ValidateSetting("limit.guest_per_hour", ""); err != nil {
		t.Errorf("empty must restore the documented number: %v", err)
	}
}

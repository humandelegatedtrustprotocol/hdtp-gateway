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

// limit.contacts sizes every account's contact cap and call budget (PACT §12), so it is a knob —
// and a knob behaves like every other one: settable from the portal, overridable by the file, and
// pinned by the environment above both (SPEC §12.2). A typo restores the default rather than
// removing the cap.
func TestContactCapIsAnOwnerSettableKnob(t *testing.T) {
	c, err := load(t, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.LimitContacts != 0 || c.ContactCap() != DefaultLimitContacts || DefaultLimitContacts != 500 {
		t.Fatalf("unset should mean the default of 500: %d / %d", c.LimitContacts, c.ContactCap())
	}
	c, err = load(t, `{"limit_contacts": 200}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.ContactCap() != 200 {
		t.Errorf("file layer ignored: %d", c.ContactCap())
	}
	c, err = load(t, `{"limit_contacts": 200}`, map[string]string{"PACT_LIMIT_CONTACTS": "2500"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ContactCap() != 2500 {
		t.Errorf("environment does not beat the file: %d", c.ContactCap())
	}
	if !c.EnvPinned["limit.contacts"] {
		t.Error("an environment-set cap is not reported as pinned, so the portal would offer to change it")
	}
	// A value nobody can read is not a licence to stop counting.
	c, err = load(t, "", map[string]string{"PACT_LIMIT_CONTACTS": "lots"})
	if err != nil {
		t.Fatal(err)
	}
	if c.ContactCap() != DefaultLimitContacts {
		t.Errorf("an unreadable cap became %d instead of the default", c.ContactCap())
	}
	if err := ValidateSetting("limit.contacts", "0"); err == nil {
		t.Error("zero was accepted; it would read as the default, not as no contacts")
	}
	if err := ValidateSetting("limit.contacts", "2500"); err != nil {
		t.Errorf("a plain number was refused: %v", err)
	}
	if err := ValidateSetting("limit.contacts", ""); err != nil {
		t.Errorf("empty must restore the default: %v", err)
	}
}

// audit_archive_after (SPEC §3.11): 90 days unless set, days or a Go duration, never negative, and
// the environment beats the file like every other bootstrap value.
func TestAuditArchiveAfter(t *testing.T) {
	read := func(file string, env map[string]string) (string, error) {
		c, err := load(t, file, env)
		if err != nil {
			return "", err
		}
		d, err := ParseAuditArchiveAfter(c.AuditArchiveAfter)
		return d.String(), err
	}
	for _, tc := range []struct {
		file string
		env  map[string]string
		want string
	}{
		{"", nil, "2160h0m0s"},
		{`{"audit_archive_after": "30d"}`, nil, "720h0m0s"},
		{`{"audit_archive_after": "0s"}`, nil, "0s"},
		{`{"audit_archive_after": "30d"}`, map[string]string{"PACT_AUDIT_ARCHIVE_AFTER": "36h"}, "36h0m0s"},
	} {
		if got, err := read(tc.file, tc.env); err != nil || got != tc.want {
			t.Errorf("%s %v: %s %v, want %s", tc.file, tc.env, got, err, tc.want)
		}
	}
	for _, bad := range []string{"-1h", "-1d", "90", "ninety days", "1.5d", ""} {
		_, err := load(t, `{"audit_archive_after": "`+bad+`"}`, nil)
		if err == nil || !strings.Contains(err.Error(), RuleRange) || !strings.Contains(err.Error(), "audit_archive_after") {
			t.Errorf("audit_archive_after %q: %v, want a %s refusal naming the key", bad, err, RuleRange)
		}
	}
}

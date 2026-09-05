package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AC (P10-10d): a value pinned in the CONFIG FILE outranks a row the portal
// wrote. SPEC §12.2 states the order as `environment > file > store > defaults`,
// and settings.go's own comment promises "an operator who pins PACT_SEAL in a
// compose file must not have it silently overridden by a row in a database" —
// but only the environment layer was ever tracked, so the store beat the file.
func TestConfigFileOutranksOwnerSetSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
		"data_dir": "`+dir+`",
		"seal": "required",
		"client_cert": "required"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	none := func(string) (string, bool) { return "", false }
	cfg, err := Load(path, none)
	if err != nil {
		t.Fatal(err)
	}

	// The portal tries to relax both, and to set a knob the file left alone.
	if err := cfg.ApplyStoreSettings(map[string]string{
		"seal":        "none",
		"client_cert": "off",
		"public_url":  "https://set-by-portal.example",
	}); err != nil {
		t.Fatal(err)
	}
	if cfg.Seal != SealRequired {
		t.Errorf("a database row overrode the operator's config file: seal=%s", cfg.Seal)
	}
	if cfg.ClientCert != ClientCertRequired {
		t.Errorf("a database row overrode the operator's config file: client_cert=%s", cfg.ClientCert)
	}
	// A knob the file did NOT pin is still the owner's to set.
	if cfg.PublicURL != "https://set-by-portal.example" {
		t.Errorf("an unpinned knob stopped being owner-settable: %q", cfg.PublicURL)
	}

	// And the portal must say so rather than offering a switch that does nothing.
	var seal Effective
	for _, e := range cfg.EffectiveSettings() {
		if e.Key == "seal" {
			seal = e
		}
	}
	if !seal.Locked || !strings.Contains(seal.Reason, "configuration file") {
		t.Errorf("the settings page would offer a control that cannot work: %+v", seal)
	}
}

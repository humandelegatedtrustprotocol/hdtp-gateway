package settings

import (
	"context"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Overlay reads the owner-settable knobs without the keyring, which is right only while none of
// them is stored as a secret row: the knobs are the settings page's, and the predicate that seals
// a row is isSecretKey.
func TestNoOwnerSettableKnobIsASecretRow(t *testing.T) {
	knobs := (&core.Config{}).EffectiveSettings()
	if len(knobs) == 0 {
		t.Fatal("no owner-settable knobs; this checks nothing")
	}
	for _, k := range knobs {
		if isSecretKey(k.Key) {
			t.Errorf("%q would be sealed at rest, and Overlay, which opens no secret row, would not apply it", k.Key)
		}
	}
}

// Credentials for a supervised stdio child are stored as
// `integration.<slug>.env.<NAME>` settings rows, and environment variable names
// are UPPERCASE by universal convention — CALDAV_PASSWORD, GITHUB_TOKEN, API_KEY.
// isSecretKey compared against lowercase markers with a case-SENSITIVE
// strings.Contains, so none of them matched and every one was written to the
// settings table in plaintext, while its own comment says it "errs toward
// secrecy".
//
// The row is the evidence, not the predicate: this asserts what actually landed
// in the store.
func TestUppercaseCredentialsAreSealedAtRest(t *testing.T) {
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st, kr: openKeyringAt(t, dir)}

	const secret = "hunter2-not-in-the-clear"
	for _, key := range []string{
		"integration.cal.env.CALDAV_PASSWORD",
		"integration.gh.env.GITHUB_TOKEN",
		"integration.x.env.API_KEY",
		"integration.y.env.CLIENT_SECRET",
	} {
		if err := svc.save(ctx, key, secret); err != nil {
			t.Fatalf("save %s: %v", key, err)
		}
	}
	rows, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range rows {
		if !strings.HasPrefix(r.Key, "integration.") {
			continue
		}
		seen++
		if !r.Secret {
			t.Errorf("%s was stored UNSEALED: a credential sits in plaintext in the "+
				"settings table and in every backup of it", r.Key)
		}
		if strings.Contains(r.Value, secret) {
			t.Errorf("%s: the plaintext credential is readable in the stored value", r.Key)
		}
	}
	if seen != 4 {
		t.Fatalf("expected 4 stored rows, saw %d", seen)
	}

	// And it must still round-trip through the decrypting reader.
	vals, err := svc.Values(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if vals["integration.cal.env.CALDAV_PASSWORD"] != secret {
		t.Errorf("a sealed credential did not read back: %q",
			vals["integration.cal.env.CALDAV_PASSWORD"])
	}
}

// Every owner-settable knob saved in the store is applied at the next boot (Overlay). Overlay
// read through a reader that skipped every dotted key, so `limit.contacts` saved in the portal was
// dropped at boot: the node ran on the default while the page showed the saved value pending.
func TestEveryOwnerSettableKnobStoredIsAppliedByOverlay(t *testing.T) {
	stored := map[string]string{
		"public_url":      "https://overlay.example",
		"tunnel":          "frp",
		"seal":            "required",
		"client_cert":     "required",
		"lan_connections": "false",
		"limit.contacts":  "7",
	}
	ctx := context.Background()
	dir := t.TempDir()
	st := openStoreAt(t, dir)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, k := range core.OwnerSettableKeys() {
		v, ok := stored[k]
		if !ok {
			t.Fatalf("%s is owner-settable and this test stores no value for it", k)
		}
		if err := st.PutSetting(ctx, store.Setting{Key: k, Value: v}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutSetting(ctx, store.Setting{Key: StorageKeyQuota("acct"), Value: "1024"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load("", func(k string) (string, bool) {
		v, ok := map[string]string{"HDTP_DATA_DIR": dir}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := New(st, openKeyringAt(t, dir), cfg, func(string, string, string) {})
	if err := svc.Overlay(ctx); err != nil {
		t.Fatal(err)
	}
	var got []core.Effective
	svc.readCfg(func(c *core.Config) { got = c.EffectiveSettings() })
	for _, e := range got {
		if want := stored[e.Key]; e.Value != want {
			t.Errorf("%s: %q after Overlay, want the stored %q", e.Key, e.Value, want)
		}
	}
	pending, err := svc.Deps().Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != len(stored) || pending["limit.contacts"] != "7" {
		t.Errorf("Pending read %v, want the %d owner knobs and nothing else", pending, len(stored))
	}
}

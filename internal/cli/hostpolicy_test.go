package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// HDTP §5.3 gives the owner a choice, per identity, for what happens when a pinned contact turns
// up at a new address: `auto` follows a leaf the contact's own root signed, `ask` holds it until
// the owner decides. §12's checklist requires an implementation to run that flow "under
// `accept_new_hosts`".
//
// The node read the setting and honoured it, and nothing could SET it. `SetAccountHostPolicy` was
// called from tests and from nowhere else, so `ask` was unreachable through the shipped binary —
// every test of the `ask` flow proved something no owner could turn on. This drives the real
// thing: the CLI, over the admin socket, against a serving node, and then reads the store.
func TestAnOwnerCanChooseTheNewAddressPolicyThroughTheShippedBinary(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "d")
	cfgPath := filepath.Join(dir, "config.json")
	internal, public := freePort(t), freePort(t)
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir": "`+dataDir+
		`", "internal_bind": "`+internal+`", "public_bind": "`+public+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	startServeAt(t, dataDir, cfgPath, internal, public)
	if code, out, errb := runQuiet("account", "create", "-config", cfgPath, "-slug", "work", "-name", "Work"); code != 0 {
		t.Fatalf("create: code=%d out=%q err=%q", code, out, errb)
	}

	policyInStore := func() string {
		t.Helper()
		st, err := store.OpenSQLite(filepath.Join(dataDir, "hdtp.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		a, err := st.GetAccountBySlug(context.Background(), "work")
		if err != nil {
			t.Fatal(err)
		}
		return a.AcceptNewHosts
	}
	if got := policyInStore(); got != "auto" {
		t.Fatalf("a new identity starts at %q, want auto", got)
	}

	code, out, errb := runQuiet("account", "address", "-config", cfgPath, "-slug", "work", "-policy", "ask")
	if code != 0 {
		t.Fatalf("setting ask: code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(out, "held until you decide") {
		t.Fatalf("the CLI should say what `ask` does, got %q", out)
	}
	if got := policyInStore(); got != "ask" {
		t.Fatalf("the store says %q after `-policy ask`: the setting did not reach the place it is read from", got)
	}

	// Anything else is refused by name, and changes nothing.
	if code, _, errb := runQuiet("account", "address", "-config", cfgPath, "-slug", "work", "-policy", "sometimes"); code == 0 || !strings.Contains(errb, "auto or ask") {
		t.Fatalf("a policy that is neither must be refused by name: code=%d err=%q", code, errb)
	}
	if got := policyInStore(); got != "ask" {
		t.Fatalf("a refused value changed the policy to %q", got)
	}

	if code, _, _ := runQuiet("account", "address", "-config", cfgPath, "-slug", "work", "-policy", "auto"); code != 0 {
		t.Fatal("setting it back to auto failed")
	}
	if got := policyInStore(); got != "auto" {
		t.Fatalf("the store says %q after `-policy auto`", got)
	}
}

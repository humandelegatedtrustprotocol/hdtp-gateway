package node

// SNI selection: where the node chose the wrong key, and where two accounts
// could quietly take each other's host.

import (
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

func TestHostOfEndpointDropsThePort(t *testing.T) {
	// SNI carries a name and never a port, so a leaf naming a port must still be
	// found by its host — otherwise selection falls through to a slug heuristic
	// that picks another account's chain whenever the host's first label is not
	// the slug, and the peer refuses the chain it is handed.
	for endpoint, want := range map[string]string{
		"https://agent.alina.example/a/alina/mcp":      "agent.alina.example",
		"https://agent.alina.example:8443/a/alina/mcp": "agent.alina.example",
		"https://alina.batondeck.com/alina/mcp":        "alina.batondeck.com",
		"https://[2001:db8::1]:8443/a/alina/mcp":       "2001:db8::1",
		"https://[2001:db8::1]/a/alina/mcp":            "2001:db8::1",
	} {
		if got := hostOfEndpoint(endpoint); got != want {
			t.Errorf("hostOfEndpoint(%q) = %q, want %q", endpoint, got, want)
		}
	}
}

func TestIndexHostRefusesToTakeAnotherAccountsHost(t *testing.T) {
	// Two accounts naming one host cannot both present their chain on it.
	// The first keeps it and the clash is audited; it used to be an overwrite in
	// silence, so whichever account was indexed last answered for both and a
	// peer validating to its own pinned root refused whatever arrived.
	clock := &demoClock{t: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	d := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)

	first := d.n.accounts[d.acct.ID]
	host := hostOfEndpoint(d.endpoint())
	if d.n.byHost[host] != first {
		t.Fatalf("the account that installed the leaf holds its host")
	}
	// A second account whose leaf names the same host.
	second := &account{rec: store.Account{ID: "acc-second", Slug: "second", RootFingerprint: "sha256:second-root"}, kp: first.kp}
	before := len(d.log)
	d.n.indexHost(second)
	if d.n.byHost[host] != first {
		t.Fatalf("the host went to the second account")
	}
	clashed := false
	for _, line := range d.log[before:] {
		if strings.Contains(line, "account_host_clash") && strings.Contains(line, host) {
			clashed = true
		}
	}
	if !clashed {
		t.Fatalf("the clash was not audited: %v", d.log[before:])
	}
}

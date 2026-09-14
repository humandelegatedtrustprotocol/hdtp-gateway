package node

// SNI selection and the 1.x fan-out's reading of its own progress: two places
// where the node chose the wrong key, and one where two accounts could quietly
// take each other's host.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func TestHostOfEndpointDropsThePort(t *testing.T) {
	// SNI carries a name and never a port, so a leaf naming a port must still be
	// found by its host — otherwise selection falls through to a slug heuristic
	// that picks another account's chain whenever the host's first label is not
	// the slug, and the peer refuses the chain it is handed.
	for endpoint, want := range map[string]string{
		"https://agent.alina.example/a/alina/mcp":      "agent.alina.example",
		"https://agent.alina.example:8443/a/alina/mcp": "agent.alina.example",
		"https://alina.pact.contact/alina/mcp":         "alina.pact.contact",
		"https://[2001:db8::1]:8443/a/alina/mcp":       "2001:db8::1",
		"https://[2001:db8::1]/a/alina/mcp":            "2001:db8::1",
	} {
		if got := hostOfEndpoint(endpoint); got != want {
			t.Errorf("hostOfEndpoint(%q) = %q, want %q", endpoint, got, want)
		}
	}
}

func TestIndexHostRefusesToTakeAnotherAccountsHost(t *testing.T) {
	// Two 2.0 accounts naming one host cannot both present their chain on it.
	// The first keeps it and the clash is audited; it used to be an overwrite in
	// silence, so whichever account was indexed last answered for both and a
	// peer validating to its own pinned root refused whatever arrived.
	clock := &demoClock{t: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	d := startDemoNode(t, clock, dn, "alina", "Alina Rao", 2, 365)

	first := d.n.accounts[d.acct.ID]
	host := hostOfEndpoint(d.endpoint())
	if d.n.byHost[host] != first {
		t.Fatalf("the account that installed the leaf holds its host")
	}
	// A second account whose leaf names the same host.
	second := &account{rec: store.Account{ID: "acc-second", Slug: "second", Protocol: 2}, kp: first.kp}
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

func TestLegacyContactToldReadsItsOwnCampaign(t *testing.T) {
	// A fan-out row naming an OLDER key says the contact was told of THAT key,
	// not of the one we hold now — so it is not told. Reading it as told (which
	// "no row for this key" legitimately means) presented the current key to a
	// contact still pinning an earlier one, which its pin refuses. Two renewals
	// inside one leaf's life are all it takes.
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	d := startDemoNode(t, clock, dn, "alina", "Alina Rao", 2, 365)
	const contact = "sha256:onexcontact"

	told, err := d.n.legacyContactTold(ctx, d.acct.ID, contact, "kid-2")
	if err != nil {
		t.Fatal(err)
	}
	if !told {
		t.Fatal("no row at all: the contact pinned the current key when it was added")
	}
	// Told of kid-1, while we now hold kid-2.
	if err := d.st.UpsertRotationFanout(ctx, store.RotationFanout{
		AccountID: d.acct.ID, ContactFpr: contact, NewFpr: "kid-1", Status: "done", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	told, err = d.n.legacyContactTold(ctx, d.acct.ID, contact, "kid-2")
	if err != nil {
		t.Fatal(err)
	}
	if told {
		t.Fatal("a row for an earlier key is not this campaign: the contact still pins kid-1")
	}
	// Told of kid-2 itself: told.
	if err := d.st.UpsertRotationFanout(ctx, store.RotationFanout{
		AccountID: d.acct.ID, ContactFpr: contact, NewFpr: "kid-2", Status: "done", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	told, err = d.n.legacyContactTold(ctx, d.acct.ID, contact, "kid-2")
	if err != nil {
		t.Fatal(err)
	}
	if !told {
		t.Fatal("a done row for the current key is told")
	}
}

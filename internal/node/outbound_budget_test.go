package node

// What an account sends is held to the buckets it is held to when called (HDTP §12): to an active
// contact at that contact's rate and within the account's aggregate, and to anybody else — or with
// one of the stranger tools, whoever the row says the peer is — the account's stranger budget
// (`stranger_calls_out_per_hour`, the limits sidecar's configuration). Every client the node
// hands out carries the budget (OutboundClient → wireClient), so no call out is unbudgeted.

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

func TestTheNodesCallsOutAreBudgeted(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	ctx := context.Background()
	const friend = "sha256:friend"
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: acct.ID, Fingerprint: friend, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	n, err := New(ctx, e.options())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		root, tool string
		contact    bool
	}{
		{friend, "send_message", true},
		{friend, "tools/list", true},
		{friend, "contact_accepted", false}, // an approval's notice goes to a row the approval made active
		{friend, "request_contact", false},
		{"sha256:stranger", "send_message", false},
		{"", "redeem_invite", false},
	} {
		if got := n.outboundToContact(acct.ID, outbound.Peer{Root: c.root}, c.tool); got != c.contact {
			t.Errorf("%s to %q charged as contact=%v, want %v", c.tool, c.root, got, c.contact)
		}
	}
	client, err := n.OutboundClient(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if client.Budget == nil {
		t.Fatal("the node hands out a client with no outbound budget")
	}
	rules := limitstest.DefaultRules(t)
	strangers := int(rules.StrangerCallsOutPerHour)
	stranger := outbound.Peer{Root: "sha256:stranger"}
	for i := range strangers {
		if err := client.Budget(stranger, "request_contact"); err != nil {
			t.Fatalf("request %d refused inside %d an hour: %v", i+1, strangers, err)
		}
	}
	var limited *outbound.RateLimited
	wait := time.Duration(math.Ceil(3600/rules.StrangerCallsOutPerHour)) * time.Second
	if err := client.Budget(stranger, "request_contact"); !errors.As(err, &limited) || limited.RetryAfter != wait {
		t.Fatalf("request %d: %v, want rate_limited for %v", strangers+1, err, wait)
	}
	for i := range int(rules.ContactBurst) {
		if err := client.Budget(outbound.Peer{Root: friend}, "send_message"); err != nil {
			t.Fatalf("message %d to a contact refused inside the burst: %v", i+1, err)
		}
	}
	if err := client.Budget(outbound.Peer{Root: friend}, "send_message"); !errors.As(err, &limited) {
		t.Fatalf("a contact's burst of messages out was not held: %v", err)
	}
	// A sidecar that is down: nothing leaves, and the owner is told why, not rate_limited.
	e.limits.Stop()
	if err := client.Budget(outbound.Peer{Root: friend}, "send_message"); err == nil || errors.As(err, &limited) || !strings.HasPrefix(err.Error(), "unavailable") {
		t.Fatalf("with the sidecar down a call out was %v, want refused unavailable", err)
	}
}

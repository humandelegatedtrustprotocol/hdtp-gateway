package node

// What an account sends is held to the buckets it is held to when called (PACT §12): to an active
// contact at that contact's rate and within the account's aggregate, and to anybody else — or with
// one of the stranger tools, whoever the row says the peer is — twenty an hour. Every client the node
// hands out carries the budget (OutboundClient → wireClient), so no call out is unbudgeted.

import (
	"context"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/outbound"
	"github.com/pact-cloud/pact-gateway/internal/public"
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
	stranger := outbound.Peer{Root: "sha256:stranger"}
	for i := range public.StrangerCallsOutPerHour {
		if ok, _ := client.Budget(stranger, "request_contact"); !ok {
			t.Fatalf("request %d refused inside %d an hour", i+1, public.StrangerCallsOutPerHour)
		}
	}
	if ok, retry := client.Budget(stranger, "request_contact"); ok || retry != 3*time.Minute {
		t.Fatalf("request %d: ok=%v retry=%v, want refused for 180 s", public.StrangerCallsOutPerHour+1, ok, retry)
	}
	for i := range public.ContactBurst {
		if ok, _ := client.Budget(outbound.Peer{Root: friend}, "send_message"); !ok {
			t.Fatalf("message %d to a contact refused inside the burst", i+1)
		}
	}
	if ok, _ := client.Budget(outbound.Peer{Root: friend}, "send_message"); ok {
		t.Fatal("a contact's burst of messages out was not held")
	}
}

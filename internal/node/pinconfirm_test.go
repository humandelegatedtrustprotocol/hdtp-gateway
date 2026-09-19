package node

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/testid"
)

// PACT §14.3's confirmation rule comes with one MUST NOT, and it is the rule that
// keeps the rule itself from being a weapon: "A verifier MUST NOT treat an unanswered
// or failed confirmation as a reason to refuse a contact, or to un-pin one."
//
// The reason is that the obvious implementation of a freshness check is a denial of
// service someone else controls. If a pin lapsed when its endpoint did not answer,
// any carrier could disconnect two people by dropping one request, and an endpoint
// that is merely down — a laptop closed, a network the verifier cannot reach at this
// moment — would look exactly like a compromised one. So the pin stands, the
// confirmation is retried, and the leaf's own `notAfter` stays the only deadline that
// refuses without anybody's help.
//
// This drives the sweep at a closed port, which is a confirmation that FAILS rather
// than one that is merely late, and asserts the stored pin afterwards field by field.
// An assertion on "the pin is still there" would pass while a field moved.
func TestAnUnansweredConfirmationChangesNoPin(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "me")
	acct := accts[0]

	// A port nothing is on: bound to learn a free one, then released. Dialing it
	// fails at connect, before TLS, which is the shape of an endpoint that is down.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := probe.Addr().String()
	_ = probe.Close()

	peer := testid.NewWallet(t, "Peer")
	host := peer.Issue(t, "https://"+dead+"/mcp")
	before, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: peer.Fpr, SPKI: host.Key.Public.SPKI,
		Status: "active", Endpoint: host.Endpoint,
		Leaf: host.LeafDER, RootCert: peer.RootDER, Card: host.Card("Peer", "optional"),
	})
	if err != nil {
		t.Fatal(err)
	}

	n, _ := e.start(e.options())
	if n.syncOne(ctx, acct.ID, peer.Fpr) {
		t.Fatal("a confirmation that never reached the endpoint reported a change")
	}

	after, err := e.st.GetContact(ctx, acct.ID, peer.Fpr)
	if err != nil {
		t.Fatalf("the contact is gone after a failed confirmation: %v", err)
	}
	// Field by field, because every one of them is part of the pin §14.3 describes.
	if after.Status != "active" {
		t.Fatalf("a failed confirmation changed the status to %q", after.Status)
	}
	if after.Fingerprint != before.Fingerprint {
		t.Fatalf("the pinned root moved: %q -> %q", before.Fingerprint, after.Fingerprint)
	}
	if after.Endpoint != before.Endpoint {
		t.Fatalf("the pinned endpoint moved: %q -> %q", before.Endpoint, after.Endpoint)
	}
	if !bytes.Equal(after.SPKI, before.SPKI) {
		t.Fatal("the pinned leaf key moved on a confirmation that failed")
	}
	if !bytes.Equal(after.Leaf, before.Leaf) {
		t.Fatal("the pinned leaf moved on a confirmation that failed")
	}
	if !bytes.Equal(after.RootCert, before.RootCert) {
		t.Fatal("the pinned root certificate moved on a confirmation that failed")
	}
	if after.Card != before.Card {
		t.Fatal("the stored card moved on a confirmation that failed")
	}

	// And it is reported, because a pin that cannot be confirmed is the owner's
	// business even though it is not a refusal.
	e.mu.Lock()
	rows := strings.Join(e.rows, "\n")
	e.mu.Unlock()
	if !strings.Contains(rows, "contact:"+peer.Fpr+" unreachable") {
		t.Fatalf("a failed confirmation was not audited:\n%s", rows)
	}
}

// Who the sync sweep is for. `SyncContacts` exists to heal a card change whose announcement
// missed us, not to re-confirm pins on a timer — 2.1 asks for no proactive confirmation and
// this node does none. What it must get right is WHICH contacts it reaches: an active one is
// visited even when its endpoint answers nothing, and a blocked one is not visited at all,
// because a blocked contact is not somebody we call.
func TestTheSweepVisitsActiveContactsAndNotBlockedOnes(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "me")
	acct := accts[0]

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := probe.Addr().String()
	_ = probe.Close()

	reachable := testid.NewWallet(t, "Up")
	rh := reachable.Issue(t, "https://"+dead+"/mcp")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: reachable.Fpr, SPKI: rh.Key.Public.SPKI,
		Status: "active", Endpoint: rh.Endpoint, Leaf: rh.LeafDER,
		Card: rh.Card("Up", "optional"),
	}); err != nil {
		t.Fatal(err)
	}
	// A blocked contact is deliberately NOT swept: it is not someone we call.
	blocked := testid.NewWallet(t, "Blocked")
	bh := blocked.Issue(t, "https://"+dead+"/mcp")
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: blocked.Fpr, SPKI: bh.Key.Public.SPKI,
		Status: "blocked", Endpoint: bh.Endpoint, Leaf: bh.LeafDER,
	}); err != nil {
		t.Fatal(err)
	}

	n, _ := e.start(e.options())
	checked, changed := n.SyncContacts(ctx)
	if checked != 1 {
		t.Fatalf("the sweep checked %d pins, want exactly the one ACTIVE contact", checked)
	}
	if changed != 0 {
		t.Fatalf("an endpoint that answered nothing reported %d changes", changed)
	}
}

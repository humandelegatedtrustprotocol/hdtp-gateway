package node

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

// HDTP §14.3's confirmation rule comes with one MUST NOT, and it is the rule that
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
// This drives a refresh at a closed port, which is a confirmation that FAILS rather
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
		AccountID: acct.ID, Fingerprint: peer.Fpr, SPKI: host.Key.Public().SPKI,
		Status: "active", Endpoint: host.Endpoint,
		Leaf: host.LeafDER, RootCert: peer.RootDER, Card: host.Card("Peer", "optional"),
	})
	if err != nil {
		t.Fatal(err)
	}

	n, _ := e.start(e.options())
	found, err := n.RefreshContact(ctx, acct.ID, peer.Fpr)
	if err != nil {
		t.Fatalf("an endpoint that is down is an outcome, not an error: %v", err)
	}
	if found.Outcome != RefreshUnreachable {
		t.Fatalf("a confirmation that never reached the endpoint reported %q", found.Outcome)
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

// Who a refresh reaches: the ONE contact that was named, of the account that asked, and only
// while that contact is somebody this identity calls.
//
// There was a sweep here — every active contact of an account, on a six-hour ticker and then on
// request — and its scoping had to be got right twice: once for blocked contacts, once for a
// token narrowed to one identity that set off calls to another's. One contact, named by the
// caller, has neither problem to get wrong, and this holds it to that: the refresh dials nobody
// for a blocked contact, for a contact of another account, or for an account this node does not
// serve, and the contacts it was NOT asked about are not dialled.
func TestARefreshReachesOnlyTheContactThatWasNamed(t *testing.T) {
	ctx := context.Background()
	e, accts := newEnv(t, "mine", "theirs")

	// Two listeners that count who connects and answer nothing useful: one for the contact that
	// will be named, one for everybody who must not be called.
	listen := func() (string, *atomic.Int32) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		var dials atomic.Int32
		go func() {
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				dials.Add(1)
				_ = c.Close()
			}
		}()
		return ln.Addr().String(), &dials
	}
	namedAddr, namedDials := listen()
	otherAddr, otherDials := listen()

	pin := func(accountID, name, status, addr string) string {
		w := testid.NewWallet(t, name)
		h := w.Issue(t, "https://"+addr+"/mcp")
		if _, err := e.st.InsertContact(ctx, store.Contact{
			AccountID: accountID, Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI,
			Status: status, Endpoint: h.Endpoint, Leaf: h.LeafDER, Card: h.Card(name, "optional"),
		}); err != nil {
			t.Fatal(err)
		}
		return w.Fpr
	}
	named := pin(accts[0].ID, "Named", "active", namedAddr)
	bystander := pin(accts[0].ID, "Bystander", "active", otherAddr)
	blocked := pin(accts[0].ID, "Blocked", "blocked", otherAddr)
	theirs := pin(accts[1].ID, "Theirs", "active", otherAddr)

	n, _ := e.start(e.options())

	// Nobody is dialled for a contact this identity does not call, and it is an error — the
	// refresh was not attempted — rather than an outcome about a peer.
	for _, tc := range []struct{ why, account, fpr string }{
		{"a blocked contact", accts[0].ID, blocked},
		{"another account's contact", accts[0].ID, theirs},
		{"an account this node does not serve", "no-such-account", named},
	} {
		if _, err := n.RefreshContact(ctx, tc.account, tc.fpr); err == nil {
			t.Errorf("%s was refreshed", tc.why)
		}
	}
	if got := namedDials.Load() + otherDials.Load(); got != 0 {
		t.Fatalf("%d connection(s) were made for contacts that must not be called", got)
	}

	found, err := n.RefreshContact(ctx, accts[0].ID, named)
	if err != nil {
		t.Fatal(err)
	}
	if found.Outcome != RefreshUnreachable {
		t.Fatalf("an endpoint that hangs up reported %q", found.Outcome)
	}
	if namedDials.Load() == 0 {
		t.Fatal("the named contact was never dialled, so the zeroes here prove nothing")
	}
	if got := otherDials.Load(); got != 0 {
		t.Fatalf("refreshing one contact made %d connection(s) to the others", got)
	}
	e.mu.Lock()
	rows := strings.Join(e.rows, "\n")
	e.mu.Unlock()
	for _, fpr := range []string{bystander, blocked, theirs} {
		if strings.Contains(rows, "contact:"+fpr) {
			t.Errorf("a refresh of one contact left an audit row about another (%s):\n%s", fpr, rows)
		}
	}
}

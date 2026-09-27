package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// PACT §9.2's handshake after an import, over the wire between three whole nodes. Alina's contacts
// arrived in an import, so they are owed word from this host once its next leaf is installed —
// here a RENEWAL at the same address, which is not a move and used to start no campaign at all.
//
//   - Bharat pins Alina's root: update_contact is accepted, and he is told.
//
//   - Chitra does not: update_contact is a contact-tier tool and she refuses it, so the campaign
//     falls back to request_contact, Alina's row waits as pending_out, and Chitra's owner has the
//     request in front of her. She accepts, Alina takes the answer, and they talk.
//
//   - Dmitri does not either, and his owner rejects: Alina's row is demoted to blocked, and an
//     unblock restores him, because the import said he had been a contact.
//
//   - Erin's leaf did not travel: nothing can be sealed to her, so she is recorded `unreached`
//     once, counted apart by `account announce`, and stays pinned by her root.
//
// The three with a leaf are told, each audit row says which way, and the marks are cleared so the campaign
// after this one is an ordinary one.
func TestAfterAnImportTheNextLeafHandshakesEveryImportedContact(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	chitra := startDemoNode(t, clock, dn, "chitra", "Chitra Iyer", 365)
	dmitri := startDemoNode(t, clock, dn, "dmitri", "Dmitri Volkov", 365)
	bharat.pinPeer(alina)

	for _, peer := range []*demoNode{bharat, chitra, dmitri} {
		if err := alina.st.ImportContact(ctx, store.Contact{
			AccountID: alina.acct.ID, Fingerprint: peer.rootFpr(), SPKI: peer.leafSPKI(), Status: "active",
			TrustFlag: "messages_only", DisplayName: peer.acct.DisplayName, Endpoint: peer.endpoint(),
			Leaf: peer.leaf(), RootCert: peer.rc, EverActive: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Erin's leaf did not travel (export_read nulls one that does not validate): she is pinned by
	// her root alone, and nothing can be sealed to her.
	erin := startDemoNode(t, clock, dn, "erin", "Erin Walsh", 365)
	if err := alina.st.ImportContact(ctx, store.Contact{
		AccountID: alina.acct.ID, Fingerprint: erin.rootFpr(), Status: "active", TrustFlag: "messages_only",
		DisplayName: erin.acct.DisplayName, Endpoint: erin.endpoint(), RootCert: erin.rc, EverActive: true,
	}); err != nil {
		t.Fatal(err)
	}

	clock.advance(time.Hour)
	res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	if res.Moved || res.HandshakesDue != 4 {
		t.Fatalf("a renewal after an import must owe the four imported contacts a handshake and not be a move: %+v", res)
	}
	done, failed, err := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid)
	if err != nil || done != 3 || failed != 0 { // erin is neither: she is unreached
		t.Fatalf("the handshake: done=%d failed=%d err=%v\n%s", done, failed, err, strings.Join(alina.log, "\n"))
	}
	trail := strings.Join(alina.log, "\n")
	for _, want := range []string{
		"account_move_fanout account:" + alina.acct.ID + " contact:" + bharat.rootFpr() + " → updated",
		"account_move_fanout account:" + alina.acct.ID + " contact:" + chitra.rootFpr() + " → requested",
		"account_move_fanout account:" + alina.acct.ID + " contact:" + erin.rootFpr() + " why:no leaf held → unreached",
	} {
		if !strings.Contains(trail, want) {
			t.Fatalf("missing from alina's trail: %q\n%s", want, trail)
		}
	}
	// Bharat followed the renewal; Chitra holds Alina's request, and nothing more.
	if c := bharat.contact(alina.rootFpr()); string(c.Leaf) != string(alina.leaf()) {
		t.Fatal("bharat did not take the new leaf the handshake carried")
	}
	if c := chitra.contact(alina.rootFpr()); c.Status != "pending_in" {
		t.Fatalf("chitra must hold alina's request for her owner to decide: %q", c.Status)
	}
	if c := alina.contact(chitra.rootFpr()); c.Status != "pending_out" {
		t.Fatalf("alina must hold chitra as an approach awaiting her answer: %q", c.Status)
	}
	// `account announce` reads this: Bharat told; Erin counted apart, never waiting, never retried.
	prog, err := alina.n.MoveProgress(ctx, alina.acct.ID, res.Kid)
	if err != nil {
		t.Fatal(err)
	}
	if prog.Told != 1 || prog.Waiting != 0 || prog.NoLeaf != 1 {
		t.Fatalf("the campaign's ledger: told=%d waiting=%d no_leaf=%d, want 1, 0, 1", prog.Told, prog.Waiting, prog.NoLeaf)
	}
	if c := alina.contact(erin.rootFpr()); c.Status != "active" || c.Fingerprint != erin.rootFpr() {
		t.Fatalf("erin must stay pinned by her root: %+v", c)
	}
	for _, peer := range []*demoNode{bharat, chitra, dmitri, erin} {
		if alina.contact(peer.rootFpr()).HandshakeDue {
			t.Fatalf("%s was told and is still owed a handshake", peer.slug)
		}
	}
	// A request that is refused is a refusal, never a request that landed: Chitra already has one.
	peer, err := alina.n.peerOf(alina.acct.ID, alina.contact(chitra.rootFpr()))
	if err != nil {
		t.Fatal(err)
	}
	err = alina.n.RequestContact(ctx, alina.acct.ID, peer, "", "again")
	if code, refused := requestRefusal(err); !refused || code != "pending_approval" {
		t.Fatalf("a second request to a peer still deciding must come back refused as pending_approval: %v", err)
	}
	// Chitra's owner accepts, and says so: the other end of the fallback. Alina takes the answer
	// and the conversation carries on both ways.
	if ok, err := chitra.st.MoveContactStatus(ctx, chitra.acct.ID, alina.rootFpr(), "pending_in", "active"); err != nil || !ok {
		t.Fatalf("chitra's approval: %v %v", ok, err)
	}
	if err := chitra.st.UpdateContactPermissions(ctx, chitra.acct.ID, alina.rootFpr(), []string{"message.text"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := chitra.n.Invalidate(ctx, chitra.acct.ID, alina.rootFpr()); err != nil {
		t.Fatal(err)
	}
	clientC, err := chitra.n.OutboundClient(chitra.acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	peerA, err := chitra.n.peerOf(chitra.acct.ID, chitra.contact(alina.rootFpr()))
	if err != nil {
		t.Fatal(err)
	}
	ans, err := clientC.Call(ctx, peerA, "contact_accepted", map[string]any{"card": chitra.card(), "permissions": []string{"message.text"}}, "accepted-c")
	if err != nil || ans.IsError {
		code, _ := refusalCodeOf(ans)
		t.Fatalf("alina refused chitra's acceptance of the handshake's request: %v %q\n%s", err, code, strings.Join(alina.log, "\n"))
	}
	if c := alina.contact(chitra.rootFpr()); c.Status != "active" {
		t.Fatalf("after chitra accepted, alina holds her as %q", c.Status)
	}
	alina.send(chitra, chitra.rootFpr(), "a-c1", "hello chitra, from my new host")
	if !chitra.received("hello chitra, from my new host") {
		t.Fatal("chitra did not receive alina's message after accepting")
	}
	// Dmitri's owner rejects under his own policy, and says so. Alina's approach is demoted to
	// blocked (PACT §5.1); since the import said he had been a contact, an unblock restores him
	// rather than forgetting him — the ordinary demotion rule.
	if ok, err := dmitri.st.MoveContactStatus(ctx, dmitri.acct.ID, alina.rootFpr(), "pending_in", "blocked"); err != nil || !ok {
		t.Fatalf("dmitri's rejection: %v %v", ok, err)
	}
	if err := dmitri.n.Invalidate(ctx, dmitri.acct.ID, alina.rootFpr()); err != nil {
		t.Fatal(err)
	}
	clientD, err := dmitri.n.OutboundClient(dmitri.acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	peerAD, err := dmitri.n.peerOf(dmitri.acct.ID, dmitri.contact(alina.rootFpr()))
	if err != nil {
		t.Fatal(err)
	}
	if ans, err := clientD.Call(ctx, peerAD, "contact_rejected", map[string]any{}, "rejected-d"); err != nil || ans.IsError {
		code, _ := refusalCodeOf(ans)
		t.Fatalf("alina refused dmitri's rejection of the handshake's request: %v %q", err, code)
	}
	if c := alina.contact(dmitri.rootFpr()); c.Status != "blocked" {
		t.Fatalf("after dmitri rejected, alina holds him as %q, want blocked", c.Status)
	}
	if d, err := (contacts.Owner{Manager: &contacts.Manager{Store: alina.st}}).Unblock(ctx, alina.acct.ID, dmitri.rootFpr()); err != nil || d.Status != "active" {
		t.Fatalf("unblocking a contact the import said was once active: %+v %v", d, err)
	}
	// And the next leaf is ordinary: nobody is owed anything.
	clock.advance(time.Hour)
	if res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now()); res.HandshakesDue != 0 || res.Moved {
		t.Fatalf("the leaf after the handshake still owes one: %+v", res)
	}
}

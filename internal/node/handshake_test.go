package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
)

// PACT §9.2's handshake after an import, over the wire between three whole nodes. Alina's contacts
// arrived in an import, so they are owed word from this host once its next leaf is installed —
// here a RENEWAL at the same address, which is not a move and used to start no campaign at all.
//
//   - Bharat pins Alina's root: update_contact is accepted, and he is told.
//   - Chitra does not: update_contact is a contact-tier tool and she refuses it, so the campaign
//     falls back to request_contact and Chitra's owner now has Alina's request in front of her.
//
// Both are told, each audit row says which way, and the marks are cleared so the campaign after
// this one is an ordinary one.
func TestAfterAnImportTheNextLeafHandshakesEveryImportedContact(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	chitra := startDemoNode(t, clock, dn, "chitra", "Chitra Iyer", 365)
	bharat.pinPeer(alina)

	for _, peer := range []*demoNode{bharat, chitra} {
		if err := alina.st.ImportContact(ctx, store.Contact{
			AccountID: alina.acct.ID, Fingerprint: peer.rootFpr(), SPKI: peer.leafSPKI(), Status: "active",
			TrustFlag: "messages_only", DisplayName: peer.acct.DisplayName, Endpoint: peer.endpoint(),
			Leaf: peer.leaf(), RootCert: peer.rc, EverActive: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	clock.advance(time.Hour)
	res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	if res.Moved || res.HandshakesDue != 2 {
		t.Fatalf("a renewal after an import must owe the two imported contacts a handshake and not be a move: %+v", res)
	}
	done, failed, err := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid)
	if err != nil || done != 2 || failed != 0 {
		t.Fatalf("the handshake: done=%d failed=%d err=%v\n%s", done, failed, err, strings.Join(alina.log, "\n"))
	}
	trail := strings.Join(alina.log, "\n")
	for _, want := range []string{
		"account_move_fanout account:" + alina.acct.ID + " contact:" + bharat.rootFpr() + " → updated",
		"account_move_fanout account:" + alina.acct.ID + " contact:" + chitra.rootFpr() + " → requested",
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
	for _, peer := range []*demoNode{bharat, chitra} {
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
	// And the next leaf is ordinary: nobody is owed anything.
	clock.advance(time.Hour)
	if res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now()); res.HandshakesDue != 0 || res.Moved {
		t.Fatalf("the leaf after the handshake still owes one: %+v", res)
	}
}

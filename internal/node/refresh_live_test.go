package node

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/identity"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
)

// "Refresh now", over a real wire between two nodes, for each thing it can find that is not a
// failure. The trust decision has its own test without a wire (`TestVerifyRefreshedCard`); this is
// the rest of the claim the button makes — that the outcome it names is what happened to the pin.
func TestRefreshingOneContactOverTheWire(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)

	// Paired through an invite, so Alina answers Bharat as a contact; `get_card` is a contact's tool.
	token := alina.invite(true)
	clientB, _ := bharat.n.OutboundClient(bharat.acct.ID)
	peerA := outbound.Peer{Endpoint: alina.endpoint(), Seal: "required", Root: alina.rootFpr(), Leaf: alina.leaf()}
	if res, err := clientB.SealedCall(ctx, peerA, "redeem_invite", map[string]any{"token": token, "card": bharat.card()}, "redeem-b"); err != nil || res.IsError {
		t.Fatalf("redeem: %v %+v", err, res)
	}
	bharat.pin20(alina)
	refresh := func(want string) {
		t.Helper()
		found, err := bharat.n.RefreshContact(ctx, bharat.acct.ID, alina.rootFpr())
		if err != nil {
			t.Fatalf("want %s: %v", want, err)
		}
		if found.Outcome != want {
			t.Fatalf("the refresh reported %q (%s), want %q\n%s", found.Outcome, found.Why, want, strings.Join(bharat.log, "\n"))
		}
	}

	// --- unchanged: she serves the card he holds ---
	before := bharat.contact(alina.rootFpr())
	refresh(RefreshUnchanged)
	if after := bharat.contact(alina.rootFpr()); after.Card != before.Card || !bytes.Equal(after.Leaf, before.Leaf) || after.PinnedAt != before.PinnedAt {
		t.Fatal("a refresh that found nothing changed wrote to the pin")
	}

	// --- updated: the card he holds is an older one of hers, under the same leaf ---
	stale, err := contacts.BuildCard20("Alina R.", alina.leaf(), "required")
	if err != nil {
		t.Fatal(err)
	}
	if err := bharat.st.UpdateContactCard(ctx, bharat.acct.ID, alina.rootFpr(), stale, "Alina R."); err != nil {
		t.Fatal(err)
	}
	refresh(RefreshUpdated)
	if c := bharat.contact(alina.rootFpr()); c.Card != alina.card() || c.DisplayName != "Alina Rao" {
		t.Fatalf("an updated card was reported and not stored: name %q", c.DisplayName)
	}

	// --- renewed: a fresh key under a newer leaf from the same root, at the same address ---
	oldLeaf := alina.leaf()
	clock.advance(time.Hour)
	if ren := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now()); !ren.KeyChanged {
		t.Fatalf("renewal: %+v", ren)
	}
	refresh(RefreshRenewed)
	c := bharat.contact(alina.rootFpr())
	if bytes.Equal(c.Leaf, oldLeaf) || !bytes.Equal(c.Leaf, alina.leaf()) || !bytes.Equal(c.SPKI, alina.leafSPKI()) {
		t.Fatal("a renewal was reported and the pin does not hold her current leaf and its key")
	}
	if c.Card != alina.card() {
		t.Fatal("a renewal was reported and the stored card is not the one carrying the new leaf")
	}
	if c.Endpoint != before.Endpoint || c.Fingerprint != before.Fingerprint {
		t.Fatal("a refresh moved the root or the address")
	}
	// And once more: the renewal has been learned, so there is nothing left to find.
	refresh(RefreshUnchanged)
}

package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// A send to a contact the account does not hold is ErrUnknownContact, and to one that is not
// active ErrNotActive naming its status: each satisfies errors.Is with the contacts sentinel the
// doors code (not_found, conflict), and keeps its text. Both were bare fmt.Errorf values a door
// could only answer internal. The control, a send to an active contact, is delivered.
func TestASendIsRefusedByCodeForAContactNotHeldOrNotActive(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	if _, err := bharat.st.InsertContact(ctx, store.Contact{AccountID: bharat.acct.ID, Fingerprint: "sha256:waiting",
		Status: "pending_out", CreatedAt: clock.t.Unix()}); err != nil {
		t.Fatal(err)
	}
	in := func(id string) messaging.Input {
		return messaging.Input{MsgID: id, Text: "hi", Origin: messaging.OriginMCP}
	}

	_, unknown := bharat.n.SendMessage(ctx, bharat.acct.ID, "sha256:nobody", in("u1"))
	_, unknownMedia := bharat.n.SendMedia(ctx, bharat.acct.ID, "sha256:nobody", in("u2"), "a.txt", "text/plain", []byte("x"))
	for _, err := range []error{unknown, unknownMedia} {
		if !errors.Is(err, ErrUnknownContact) || !errors.Is(err, contacts.ErrUnknownContact) || err.Error() != "send: unknown contact" {
			t.Errorf("a contact not held: %v, want ErrUnknownContact (contacts.ErrUnknownContact)", err)
		}
	}
	_, waiting := bharat.n.SendMessage(ctx, bharat.acct.ID, "sha256:waiting", in("w1"))
	_, waitingMedia := bharat.n.SendMedia(ctx, bharat.acct.ID, "sha256:waiting", in("w2"), "a.txt", "text/plain", []byte("x"))
	for _, err := range []error{waiting, waitingMedia} {
		if !errors.Is(err, ErrNotActive) || !errors.Is(err, contacts.ErrWrongState) || errors.Is(err, contacts.ErrUnknownContact) ||
			err.Error() != "send: contact is pending_out, not active" {
			t.Errorf("a contact not active: %v, want ErrNotActive (contacts.ErrWrongState) naming pending_out", err)
		}
	}

	// The control.
	token := alina.invite(true)
	clientB, _ := bharat.n.OutboundClient(bharat.acct.ID)
	peerA := outbound.Peer{Endpoint: alina.endpoint(), Seal: "required", Root: alina.rootFpr(), Leaf: alina.leaf()}
	if res, err := clientB.SealedCall(ctx, peerA, "redeem_invite", map[string]any{"token": token, "card": bharat.card()}, "redeem-b"); err != nil || res.IsError {
		t.Fatalf("redeem: %v %+v", err, res)
	}
	bharat.pinPeer(alina)
	if res, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), in("ok")); err != nil || res.Status != StatusDelivered {
		t.Fatalf("the control: %v %+v", err, res)
	}
}

package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// A send to a contact the account does not hold is ErrUnknownContact, and to one that is not
// active an error naming its status: each satisfies errors.Is with the contacts sentinel the doors
// code (not_found, conflict), and keeps its text. Both were bare fmt.Errorf values a door
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
		if !errors.Is(err, contacts.ErrWrongState) || errors.Is(err, contacts.ErrUnknownContact) ||
			err.Error() != "send: contact is pending_out, not active" {
			t.Errorf("a contact not active: %v, want contacts.ErrWrongState naming pending_out", err)
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

	// Recorded and not delivered: the result comes back (its thread, pending) with the reason the
	// node names, which a door answers unavailable; the dial's text stays in Error() for the audit.
	dn.set(alina.host, "127.0.0.1:1")
	res, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), in("down"))
	if why, ok := refusal.Why(err); !ok || why != WhyUnreachable || res.ThreadID == "" || res.Status != StatusPending {
		t.Errorf("an unreachable contact: %v (why %q) %+v, want a pending result and %q", err, why, res, WhyUnreachable)
	}
}

// A peer's refusal names its §12 code as the reason when the code has the protocol's shape, and
// "refused" otherwise, so a peer cannot put words of its own in front of the owner.
func TestAPeersRefusalIsNamedByItsCode(t *testing.T) {
	refused := func(body string) error {
		return peerRefusal(&mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: body}}})
	}
	for _, c := range []struct{ body, why string }{
		{`{"code":"permission_denied"}`, "permission_denied"},
		{`{"code":"Send <b>me</b> money"}`, WhyRefused},
		{`not json`, WhyRefused},
	} {
		if why, ok := refusal.Why(refused(c.body)); !ok || why != c.why {
			t.Errorf("%s: why %q (%v), want %q", c.body, why, ok, c.why)
		}
	}
	if err := peerRefusal(&mcp.CallToolResult{}); err != nil {
		t.Errorf("the control, an answer that is no refusal: %v", err)
	}
}

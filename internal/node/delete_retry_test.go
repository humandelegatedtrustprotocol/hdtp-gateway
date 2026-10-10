package node

import (
	"context"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// A message still waiting to be delivered in a conversation the owner deletes is never sent: the
// deletion takes it with the thread, so the retry sweep has nothing to try (SPEC §7.9).
func TestAMessageWaitingInADeletedConversationIsNeverSent(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	token := alina.invite(true)
	clientB, _ := bharat.n.OutboundClient(bharat.acct.ID)
	peerA := outbound.Peer{Endpoint: alina.endpoint(), Seal: "required", Root: alina.rootFpr(), Leaf: alina.leaf()}
	if res, err := clientB.SealedCall(ctx, peerA, "redeem_invite", map[string]any{"token": token, "card": bharat.card()}, "redeem-b"); err != nil || res.IsError {
		t.Fatalf("redeem: %v %+v", err, res)
	}
	bharat.pinPeer(alina)

	addr := dn.hosts[alina.host]
	dn.set(alina.host, "127.0.0.1:1")
	late, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: "d1", Text: "never mind", Origin: messaging.OriginMCP})
	if err == nil {
		t.Fatalf("a send to an address that does not answer was delivered: %+v", late)
	}
	if pending, _ := bharat.st.ListPendingOutbound(ctx, 10); len(pending) != 1 {
		t.Fatalf("%d messages waiting, want the one undelivered", len(pending))
	}
	svc := &messaging.Service{Store: bharat.st}
	if _, err := svc.DeleteThread(ctx, bharat.acct.ID, late.ThreadID); err != nil {
		t.Fatal(err)
	}
	dn.set(alina.host, addr)
	clock.advance(time.Hour)
	if delivered, expired := bharat.n.RetryPending(ctx); delivered != 0 || expired != 0 {
		t.Fatalf("the sweep delivered %d and expired %d messages of a deleted conversation", delivered, expired)
	}
	if _, err := alina.st.GetMessageByMsgID(ctx, alina.acct.ID, bharat.rootFpr(), "in", "d1"); err == nil {
		t.Fatal("the peer received a message from a conversation deleted before it was delivered")
	}
}

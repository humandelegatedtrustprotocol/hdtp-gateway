package node

import (
	"context"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// HDTP §7 between two nodes, through the send both owner doors call (#232): a send without
// thread_id starts a new thread, under the same id on both sides; a send naming a thread continues
// it on both sides, from either end. Each side ends holding the same two threads and nothing else.
func TestASendContinuesTheThreadItNamesOnBothNodes(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
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

	send := func(from, to *demoNode, msgID, thread string) string {
		t.Helper()
		res, err := from.n.SendMessage(ctx, from.acct.ID, to.rootFpr(), messaging.Input{MsgID: msgID, ThreadID: thread, Text: msgID, Origin: messaging.OriginMCP})
		if err != nil || res.Status != messaging.StatusDelivered {
			t.Fatalf("%s → %s %s: %v %+v", from.slug, to.slug, msgID, err, res)
		}
		return res.ThreadID
	}
	holds := func(d *demoNode, thread string, want int) {
		t.Helper()
		msgs, err := d.n.opts.Store.ListMessagesByThread(ctx, d.acct.ID, thread)
		if err != nil || len(msgs) != want {
			t.Fatalf("%s holds %d messages in %s (%v), want %d", d.slug, len(msgs), thread, err, want)
		}
	}

	first := send(bharat, alina, "b1", "")
	second := send(bharat, alina, "b2", "")
	if second == first {
		t.Fatalf("a second send without thread_id continued %s", first)
	}
	if got := send(bharat, alina, "b3", first); got != first {
		t.Fatalf("bharat's send naming %s went to %s", first, got)
	}
	if got := send(alina, bharat, "a1", first); got != first {
		t.Fatalf("alina's reply naming %s went to %s", first, got)
	}
	for _, d := range []*demoNode{alina, bharat} {
		holds(d, first, 3)
		holds(d, second, 1)
		threads, err := d.n.opts.Store.ListThreadsByAccount(ctx, d.acct.ID)
		if err != nil || len(threads) != 2 {
			t.Fatalf("%s holds %d threads (%v), want 2", d.slug, len(threads), err)
		}
	}
}

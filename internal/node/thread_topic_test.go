package node

import (
	"context"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// SPEC §7: a thread's topic is the one given when it was created, stored by both sides. The owner's
// send took none, so every thread the owner started had none on either side; and a first attempt
// that failed would have reached the peer without it on the retry, whose input carries no topic.
func TestAThreadsTopicReachesThePeerOnTheFirstAttemptAndOnARetry(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
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

	topicAt := func(d *demoNode, threadID string) string {
		th, err := d.st.GetThread(ctx, d.acct.ID, threadID)
		if err != nil {
			return "<no thread>"
		}
		return th.Topic
	}

	first, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: "t1", Text: "coffee?", Topic: "Coffee catch-up", Origin: messaging.OriginMCP})
	if err != nil || first.Status != StatusDelivered {
		t.Fatalf("send: %v %+v", err, first)
	}
	if got := topicAt(bharat, first.ThreadID); got != "Coffee catch-up" {
		t.Fatalf("our thread's topic = %q", got)
	}
	if got := topicAt(alina, first.ThreadID); got != "Coffee catch-up" {
		t.Fatalf("the peer's thread's topic = %q", got)
	}

	addr := dn.hosts[alina.host]
	dn.set(alina.host, "127.0.0.1:1")
	late, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: "t2", Text: "later", Topic: "Later", Origin: messaging.OriginMCP})
	if err == nil {
		t.Fatalf("a send to an address that does not answer was delivered: %+v", late)
	}
	dn.set(alina.host, addr)
	clock.advance(time.Hour)
	if delivered, _ := bharat.n.RetryPending(ctx); delivered != 1 {
		t.Fatalf("the retry delivered %d messages, want 1", delivered)
	}
	if got := topicAt(alina, late.ThreadID); got != "Later" {
		t.Fatalf("the peer's thread's topic after the retry = %q", got)
	}
}

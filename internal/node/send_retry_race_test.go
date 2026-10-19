package node

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
)

// pairedForRetry is bharat holding alina as an active contact, as the retry tests need.
func pairedForRetry(t *testing.T) (alina, bharat *demoNode, dn *demoNet, clock *demoClock) {
	t.Helper()
	clock = &demoClock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	dn = &demoNet{hosts: map[string]string{}}
	alina = startDemoNode(t, clock, dn, "alina", "Alina Rao", 30)
	bharat = startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	token := alina.invite(true)
	clientB, _ := bharat.n.OutboundClient(bharat.acct.ID)
	peerA := outbound.Peer{Endpoint: alina.endpoint(), Seal: "required", Root: alina.rootFpr(), Leaf: alina.leaf()}
	if res, err := clientB.SealedCall(context.Background(), peerA, "redeem_invite", map[string]any{"token": token, "card": bharat.card()}, "redeem-b"); err != nil || res.IsError {
		t.Fatalf("redeem: %v %+v", err, res)
	}
	bharat.pinPeer(alina)
	return alina, bharat, dn, clock
}

// sealedCalls is how many sealed calls have reached d: every send is one, on the wire, whatever the
// receiver then makes of a msg_id it has seen.
func sealedCalls(d *demoNode) int {
	d.hookMu.Lock()
	defer d.hookMu.Unlock()
	return len(d.kids)
}

// outcomes counts bharat's send_message audit rows by outcome.
func outcomes(d *demoNode) map[string]int {
	got := map[string]int{}
	for _, line := range d.log {
		if action, rest, ok := strings.Cut(line, " "); ok && action == "send_message" {
			if _, outcome, ok := strings.Cut(rest, " → "); ok {
				got[outcome]++
			}
		}
	}
	return got
}

// #219: a retry sweep that runs while a send's first attempt is still under way does not send
// the message a second time. It did: the sweep's list held the message as pending with no attempt
// made, so it sent it again with the same msg_id. The receiver turned the duplicate into the
// original acknowledgment (HDTP §7.2), and the sender's audit trail read `delivered`, then
// `delivered_on_retry`, for one message that was sent twice.
func TestASweepDuringTheFirstAttemptDoesNotSendTheMessageAgain(t *testing.T) {
	ctx := context.Background()
	alina, bharat, _, _ := pairedForRetry(t)
	before := sealedCalls(alina)

	// The receiver's handler is the one place the first attempt is certainly in flight. The sweep
	// runs from there, and the handler waits until the sweep has either finished or claimed its
	// own attempt, so the two attempts overlap whichever way the sweep goes.
	attempts := func() int64 {
		m, err := bharat.st.GetMessageByMsgID(ctx, bharat.acct.ID, alina.rootFpr(), "out", "r1")
		if err != nil {
			return -1
		}
		return m.Attempts
	}
	var once sync.Once
	swept := make(chan int, 1)
	alina.onAudit(func(string) {
		once.Do(func() {
			was := attempts()
			go func() {
				delivered, _ := bharat.n.RetryPending(ctx)
				swept <- delivered
			}()
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
				if len(swept) > 0 || attempts() != was {
					return
				}
			}
		})
	})
	res, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: "r1", Text: "on my way", Origin: messaging.OriginMCP})
	if err != nil || res.Status != messaging.StatusDelivered {
		t.Fatalf("the send: %+v, %v", res, err)
	}
	var delivered int
	select {
	case delivered = <-swept:
	case <-time.After(40 * time.Second):
		t.Fatal("the sweep did not finish")
	}
	if delivered != 0 {
		t.Errorf("the sweep delivered %d messages, want 0: the first attempt was still under way", delivered)
	}
	if got := sealedCalls(alina) - before; got != 1 {
		t.Errorf("the receiver was sent the message %d times, want 1", got)
	}
	if got := outcomes(bharat); got["delivered"] != 1 || got["delivered_on_retry"] != 0 {
		t.Errorf("the sender's audit trail: %v, want one delivered and no delivered_on_retry", got)
	}
}

// The control: a first attempt that really fails holds the message only for its budget. Before
// that the sweep leaves it; just after it, the sweep delivers it, once.
func TestAFailedFirstAttemptIsRetriedOnceItsHoldEnds(t *testing.T) {
	ctx := context.Background()
	alina, bharat, dn, clock := pairedForRetry(t)
	addr := dn.hosts[alina.host]
	dn.set(alina.host, "127.0.0.1:1")
	if _, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: "r2", Text: "still there?", Origin: messaging.OriginMCP}); err == nil {
		t.Fatal("a send to an address that does not answer was delivered")
	}
	dn.set(alina.host, addr)
	before := sealedCalls(alina)

	// Sent again under its msg_id while the hold lasts, it is not attempted: it is answered as it
	// stands, pending, and the sweep goes on with it.
	if res, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: "r2", Text: "still there?", Origin: messaging.OriginMCP}); err != nil || res.Status != messaging.StatusPending {
		t.Fatalf("the send replayed during the hold: %+v, %v; want pending and no error", res, err)
	}
	if got := sealedCalls(alina) - before; got != 0 {
		t.Fatalf("the send replayed during the hold reached the receiver %d times", got)
	}

	clock.advance(deliveryBudget - time.Second)
	if delivered, _ := bharat.n.RetryPending(ctx); delivered != 0 {
		t.Fatalf("the sweep delivered %d messages while the first attempt's hold lasted", delivered)
	}
	clock.advance(time.Second)
	if delivered, _ := bharat.n.RetryPending(ctx); delivered != 1 {
		t.Fatalf("the sweep delivered %d messages once the hold ended, want 1", delivered)
	}
	if delivered, _ := bharat.n.RetryPending(ctx); delivered != 0 {
		t.Fatalf("a second sweep delivered %d messages already delivered", delivered)
	}
	if got := sealedCalls(alina) - before; got != 1 {
		t.Errorf("the receiver was sent the message %d times, want 1", got)
	}
	if got := outcomes(bharat); got["undelivered"] != 1 || got["pending"] != 1 || got["delivered_on_retry"] != 1 || got["delivered"] != 0 {
		t.Errorf("the sender's audit trail: %v, want one undelivered, one pending, then one delivered_on_retry", got)
	}
	if !alina.received("still there?") {
		t.Error("the receiver does not hold the message")
	}
}

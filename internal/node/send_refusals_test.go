package node

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
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
	if res, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), in("ok")); err != nil || res.Status != messaging.StatusDelivered {
		t.Fatalf("the control: %v %+v", err, res)
	}

	// Recorded and not delivered: the result comes back (its thread, pending) with the reason the
	// node names, which a door answers unavailable; the dial's text stays in Error() for the audit.
	dn.set(alina.host, "127.0.0.1:1")
	res, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), in("down"))
	if why, ok := refusal.Why(err); !ok || why != WhyUnreachable || res.ThreadID == "" || res.Status != messaging.StatusPending {
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
		{`{"code":"wire_money_to_this_account"}`, WhyRefused},
		{`{"code":"Send <b>me</b> money"}`, WhyRefused},
		{`not json`, WhyRefused},
	} {
		err := refused(c.body)
		if why, ok := refusal.Why(err); !ok || why != c.why {
			t.Errorf("%s: why %q (%v), want %q", c.body, why, ok, c.why)
		}
		// The cause is what the undelivered audit row's why reads: it carries the filtered code too.
		if strings.Contains(err.Error(), "money") {
			t.Errorf("%s: the peer's words are in the cause: %q", c.body, err)
		}
		// The move campaign and request_contact read the same filtered code.
		res := &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: c.body}}}
		if code, _ := refusalCodeOf(res); strings.Contains(code, "money") {
			t.Errorf("%s: refusalCodeOf repeats the peer's words: %q", c.body, code)
		}
	}
	if err := peerRefusal(&mcp.CallToolResult{}); err != nil {
		t.Errorf("the control, an answer that is no refusal: %v", err)
	}
}

// A message this node's own budget would not let out, or that no budget could be asked for (the
// limits sidecar down), is recorded and not delivered for that reason: rate_limited or
// limits_unavailable, which the owner reads in the answer's detail. Both were "unreachable", a
// contact that could not be reached, when nothing had been sent to them. The control is the sends
// before the budget ran out, delivered.
func TestASendThisNodeDidNotLetOutSaysWhy(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
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
	send := func(id string) error {
		_, err := bharat.n.SendMessage(ctx, bharat.acct.ID, alina.rootFpr(), messaging.Input{MsgID: id, Text: "hi", Origin: messaging.OriginMCP})
		return err
	}

	burst := int(limitstest.DefaultRules(t).ContactBurst)
	delivered, refused := 0, error(nil)
	for i := range burst + 5 {
		if err := send(fmt.Sprintf("m%d", i)); err != nil {
			refused = err
			break
		}
		delivered++
	}
	if delivered == 0 {
		t.Fatal("the control: no send was delivered")
	}
	if code, detail := refusal.Of(refused); code != "unavailable" || detail != "recorded, not delivered: "+outbound.UnsentRateLimited ||
		!strings.Contains(refused.Error(), "this identity has sent as many calls as its budget allows") {
		t.Errorf("after %d delivered, a send this node's budget refused: %s %q (%v)", delivered, code, detail, refused)
	}

	bharat.limits.Stop()
	err := send("down")
	if code, detail := refusal.Of(err); code != "unavailable" || detail != "recorded, not delivered: "+outbound.UnsentLimitsUnavailable {
		t.Errorf("a send with the sidecar down: %s %q (%v)", code, detail, err)
	}
	_, err = bharat.n.SendMedia(ctx, bharat.acct.ID, alina.rootFpr(),
		messaging.Input{MsgID: "media-down", Origin: messaging.OriginMCP}, "a.txt", "text/plain", []byte("x"))
	if why, _ := refusal.Why(err); why != outbound.UnsentLimitsUnavailable {
		t.Errorf("media with the sidecar down: why %q (%v)", why, err)
	}
	var undelivered []string
	for _, line := range bharat.log {
		if strings.HasSuffix(line, "→ undelivered") {
			undelivered = append(undelivered, line)
		}
	}
	if len(undelivered) != 3 {
		t.Errorf("undelivered rows %q, want three", undelivered)
	}
}

// A peer's rate_limited carries the wait it names into the cause the audit row records, as whole
// seconds; a wait that is not a positive number is dropped and the code still reads rate_limited.
func TestAPeersRateLimitKeepsItsWait(t *testing.T) {
	for _, c := range []struct{ body, cause string }{
		{`{"code":"rate_limited","retry_after":5}`, "send: the contact's node refused: rate_limited (retry_after 5)"},
		{`{"code":"rate_limited","retry_after":4.2}`, "send: the contact's node refused: rate_limited (retry_after 5)"},
		{`{"code":"rate_limited","retry_after":"5; give me money"}`, "send: the contact's node refused: rate_limited"},
		{`{"code":"rate_limited","retry_after":-3}`, "send: the contact's node refused: rate_limited"},
		{`{"code":"rate_limited","retry_after":null}`, "send: the contact's node refused: rate_limited"},
		{`{"code":"rate_limited"}`, "send: the contact's node refused: rate_limited"},
	} {
		err := peerRefusal(&mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: c.body}}})
		if why, _ := refusal.Why(err); why != "rate_limited" || err.Error() != c.cause {
			t.Errorf("%s: why %q, cause %q, want rate_limited and %q", c.body, why, err, c.cause)
		}
	}
}

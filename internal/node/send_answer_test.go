package node

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/ownermcp"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/outbound"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/webhooks"
)

// #234 with #208. send_to_contact answers the message's message_id, and it is the one id every
// other reader carries for that message: read_thread's row, the change log's entry and the webhook
// envelope's data, on the sending node (message.delivered) and on the receiving one
// (message.received). The send goes through the owner MCP over the node's own send, to a second
// node, as the owner's agent makes it.
func TestSendToContactAnswersTheMessageIDEveryReaderCarries(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
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

	owner, err := bharat.st.CreateOwnerWithID(ctx, "", "Bharat")
	if err != nil {
		t.Fatal(err)
	}
	if err := bharat.st.AddMembership(ctx, owner.ID, bharat.acct.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	srv := ownermcp.NewServerWithExtra(ownermcp.Deps{
		Store: bharat.st, Msg: &messaging.Service{Store: bharat.st, Bus: bharat.n.Bus()}, Bus: bharat.n.Bus(),
		Send: bharat.n.SendMessage,
	}, ownermcp.Extra{}, auth.Identity{OwnerID: owner.ID})
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	call := func(tool string, args map[string]any) string {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil || res.IsError || len(res.Content) == 0 {
			t.Fatalf("%s: %v %+v", tool, err, res)
		}
		return res.Content[0].(*mcp.TextContent).Text
	}

	var sent struct {
		Status    string `json:"status"`
		MessageID string `json:"message_id"`
		ThreadID  string `json:"thread_id"`
	}
	text := call("send_to_contact", map[string]any{"account_id": bharat.acct.ID, "contact_fpr": alina.rootFpr(), "msg_id": "b-1", "text": "dinner friday?"})
	if err := json.Unmarshal([]byte(text), &sent); err != nil || sent.Status != messaging.StatusDelivered || sent.MessageID != "b-1" || sent.ThreadID == "" {
		t.Fatalf("send_to_contact answered %s, want status delivered and message_id b-1", text)
	}

	var rows []struct {
		MessageID string `json:"message_id"`
	}
	if err := json.Unmarshal([]byte(call("read_thread", map[string]any{"account_id": bharat.acct.ID, "thread_id": sent.ThreadID})), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("read_thread: %v %+v", err, rows)
	}
	logged := func(d *demoNode, kind string) (change, hook string) {
		t.Helper()
		changes, err := d.st.AccountChangesAfter(ctx, d.acct.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range changes {
			if env, ok := webhooks.EnvelopeOf(c, d.acct.ID); ok && env.Type == kind {
				id, _ := env.Data["message_id"].(string)
				return c.MsgID, id
			}
		}
		t.Fatalf("%s's change log has no %s", d.slug, kind)
		return "", ""
	}
	outChange, outHook := logged(bharat, "message.delivered")
	inChange, inHook := logged(alina, "message.received")
	for name, got := range map[string]string{
		"read_thread": rows[0].MessageID, "the sender's change log": outChange, "the sender's webhook": outHook,
		"the receiver's change log": inChange, "the receiver's webhook": inHook,
	} {
		if got != sent.MessageID {
			t.Errorf("%s names the message %q; send_to_contact answered %q", name, got, sent.MessageID)
		}
	}
}

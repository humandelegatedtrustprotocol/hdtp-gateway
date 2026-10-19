package ownermcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/webhooks"
)

// #208. read_thread's rows carried no message id, so an agent keyed its work by a message's text
// and position, which shift when retention prunes. Each row now carries message_id, and it is the
// id the change log records for that message and the one its webhook envelope's data carries: one
// message received and one sent, each read back three ways.
func TestReadThreadCarriesTheMessageIDTheChangeLogAndTheWebhookCarry(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:c", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	in, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:c", messaging.DirIn,
		messaging.Input{MsgID: "their-1", Text: "dinner?", Origin: messaging.OriginPeer, Sender: messaging.SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:c", messaging.DirOut,
		messaging.Input{MsgID: "mine-1", ThreadID: in.ThreadID, Text: "friday", Origin: messaging.OriginMCP}); err != nil {
		t.Fatal(err)
	}
	// Delivered, as the node's setStatus records it: the row's status, then the delivery event.
	if err := e.st.SetMessageStatus(ctx, e.acctA, "sha256:c", "mine-1", messaging.StatusDelivered); err != nil {
		t.Fatal(err)
	}
	e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventDelivery, AccountID: e.acctA, ContactFpr: "sha256:c",
		ThreadID: in.ThreadID, Status: messaging.StatusDelivered, MsgID: "mine-1"})

	srv := NewServerWithExtra(e.deps, Extra{}, auth.Identity{OwnerID: e.owner})
	body, isErr := callParityResult(t, ctx, srv, "read_thread", map[string]any{"account_id": e.acctA, "thread_id": in.ThreadID})
	var rows []struct {
		MessageID string `json:"message_id"`
		Direction string `json:"direction"`
	}
	if isErr || json.Unmarshal([]byte(body), &rows) != nil {
		t.Fatalf("read_thread: %s", body)
	}
	read := map[string]string{}
	for _, r := range rows {
		read[r.Direction] = r.MessageID
	}

	changes, err := e.st.AccountChangesAfter(ctx, e.acctA, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	logged, hooked := map[string]string{}, map[string]string{}
	for _, c := range changes {
		env, ok := webhooks.EnvelopeOf(c, e.acctA)
		if !ok {
			continue
		}
		switch env.Type {
		case "message.received":
			logged["in"], hooked["in"] = c.MsgID, env.Data["message_id"].(string)
		case "message.delivered":
			logged["out"], hooked["out"] = c.MsgID, env.Data["message_id"].(string)
		}
	}
	for dir, want := range map[string]string{"in": "their-1", "out": "mine-1"} {
		if read[dir] != want || logged[dir] != want || hooked[dir] != want {
			t.Errorf("the %s message: read_thread %q, the change log %q, the webhook %q; want %q all three",
				dir, read[dir], logged[dir], hooked[dir], want)
		}
	}
}

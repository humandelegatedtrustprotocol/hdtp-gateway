package node

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// A delivery-status change row names the message whose status moved, beside the status: without it
// the webhooks' `message.delivered` and `message.failed` (internal/services/webhooks) could say a
// message of the thread arrived, not which one.
func TestADeliveryStatusRowNamesItsMessage(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	msg := &messaging.Service{Store: st}
	res, err := msg.Record(ctx, a.ID, "sha256:alina", messaging.DirOut, messaging.Input{Origin: messaging.OriginPortal, MsgID: "m-out", Text: "yo"})
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{opts: Options{Store: st, Bus: messaging.NewBus(st)}}
	if err := n.setStatus(ctx, a.ID, "sha256:alina", "m-out", res.ThreadID, messaging.StatusDelivered); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ChangesAfter(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one change row, got %+v", rows)
	}
	e := messaging.EventOf(rows[0])
	if e.Kind != messaging.EventDelivery || e.Status != messaging.StatusDelivered || e.MsgID != "m-out" || e.ThreadID != res.ThreadID {
		t.Fatalf("the delivery row says %+v", e)
	}
}

package ownermcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// Build rule 1's divergence, named where a test holds it: a deleted conversation reaches the
// portal and not wait_for_updates. DeleteThread publishes a message event naming the thread, which
// a portal showing it hears; a wait reads that thread's change as nothing to read (changesSince,
// "gone since"), so it parks through the deletion and ends on the clock. The decision of the plan
// of 2026-10-16: wait_for_updates reports no deletion in this release, and BatonDeck's wait names
// none either. A wait that reports one takes this entry out.
func TestAWaitDoesNotReportADeletedConversation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:alina", messaging.DirIn,
		messaging.Input{Origin: messaging.OriginPeer, MsgID: "m1", Text: "hi", Sender: messaging.SenderAgent})
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	var start waitResult
	first, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA})
	if err := json.Unmarshal([]byte(first), &start); err != nil {
		t.Fatal(err)
	}

	portal, stop := e.deps.Bus.Subscribe(e.acctA)
	defer stop()
	if text, isErr := callJSON(t, cs, "delete_thread", map[string]any{"account_id": e.acctA, "thread_id": r.ThreadID}); isErr {
		t.Fatalf("delete_thread: %s", text)
	}
	select {
	case ev := <-portal:
		if ev.Kind != messaging.EventMessage || ev.ThreadID != r.ThreadID {
			t.Fatalf("the portal heard %+v, want a message event naming %s", ev, r.ThreadID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the deletion published nothing a portal hears")
	}

	text, isErr := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA, "since": start.Cursor, "timeout_sec": 1})
	if isErr {
		t.Fatalf("wait_for_updates: %s", text)
	}
	var got waitResult
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if !got.TimedOut || len(got.Threads) != 0 {
		t.Fatalf("the wait answered %s; if it reports a deletion now, remove this divergence", text)
	}
}

package ownermcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

func (f *failingStore) ListIntegrations(ctx context.Context, a string) ([]store.Integration, error) {
	if err := f.hit("ListIntegrations"); err != nil {
		return nil, err
	}
	return f.Store.ListIntegrations(ctx, a)
}

func (f *failingStore) CountContactsByStatus(ctx context.Context, a, status string) (int64, error) {
	if err := f.hit("CountContactsByStatus"); err != nil {
		return 0, err
	}
	return f.Store.CountContactsByStatus(ctx, a, status)
}

func (f *failingStore) ListPendingAddresses(ctx context.Context, a string) ([]store.PendingAddress, error) {
	if err := f.hit("ListPendingAddresses"); err != nil {
		return nil, err
	}
	return f.Store.ListPendingAddresses(ctx, a)
}

// wait_for_updates and digest answer a count, a list or a thread they could not read as internal
// with the fixed detail. They read each failure as nothing: no integration needing attention, no
// request waiting, a thread's unread 0, a thread's messages skipped, so a wait parked or a digest
// said all was quiet. Each row's control, the same call with nothing failing, gets through.
func TestTheWatchToolsAnswerAFailedReadAsInternal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:c", messaging.DirIn, messaging.Input{
		Origin: messaging.OriginPeer, MsgID: "m1", Text: "hi", Sender: messaging.SenderAgent}); err != nil {
		t.Fatal(err)
	}
	wait := map[string]any{"account_id": e.acctA, "since": 0, "timeout_sec": 1}
	digest := map[string]any{"account_id": e.acctA}
	for _, c := range []struct {
		tool, method string
		args         map[string]any
	}{
		{"wait_for_updates", "ListIntegrations", wait},
		{"wait_for_updates", "CountContactsByStatus", wait},
		{"wait_for_updates", "ListPendingAddresses", wait},
		{"wait_for_updates", "ListOpenPendingRequests", wait},
		{"wait_for_updates", "GetThread", wait},
		{"wait_for_updates", "UnreadCount", wait},
		{"digest", "ListMessagesByThread", digest},
		{"digest", "UnreadCount", digest},
		{"digest", "CountContactsByStatus", digest},
		{"digest", "ListPendingAddresses", digest},
		{"digest", "ListOpenPendingRequests", digest},
	} {
		run := func(fail string) (*failingStore, string, bool) {
			fs := &failingStore{Store: e.st, fail: fail, called: map[string]bool{}}
			d := e.deps
			d.Store = fs
			d.Pending = &integrations.AgentAnswered{Store: fs, Bus: e.deps.Bus, WaitBudget: time.Second}
			srv := NewServerWithExtra(d, Extra{Log: func(string, string, string) {}}, auth.Identity{OwnerID: e.owner})
			body, isErr := callParityResult(t, ctx, srv, c.tool, c.args)
			return fs, body, isErr
		}
		fs, body, isErr := run(c.method)
		if !fs.called[c.method] {
			t.Errorf("%s: never reached %s: %s", c.tool, c.method, body)
			continue
		}
		if got := noStoreText(t, c.tool+" "+c.method, body, isErr); got["code"] != "internal" || got["detail"] != refusal.InternalDetail {
			t.Errorf("%s with %s failing: %s, want internal", c.tool, c.method, body)
		}
		if _, body, isErr := run(""); isErr {
			t.Errorf("%s, the control: %s", c.tool, body)
		}
	}
}

func (f *failingStore) GetContact(ctx context.Context, a, fpr string) (store.Contact, error) {
	if err := f.hit("GetContact"); err != nil {
		return store.Contact{}, err
	}
	return f.Store.GetContact(ctx, a, fpr)
}

// A contact's call whose contact row could not be read ends the wait internal: it was skipped as if
// the contact were gone, and the cursor moved past it, so the call was never reported. The control,
// the same wait with nothing failing, reports the call of the contact the account holds and skips
// the call of one it holds no row for (removed since), with no error.
func TestAWaitAnswersAContactsCallItCouldNotReadAsInternal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:k", Status: "active",
		CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	for _, fpr := range []string{"sha256:k", "sha256:gone"} {
		e.deps.Bus.Publish(messaging.Event{Kind: messaging.EventCall, AccountID: e.acctA, ContactFpr: fpr, Ref: core.ToolBookSlot})
	}
	wait := map[string]any{"account_id": e.acctA, "since": 0, "timeout_sec": 1}
	run := func(fail string) (*failingStore, string, bool) {
		fs := &failingStore{Store: e.st, fail: fail, called: map[string]bool{}}
		d := e.deps
		d.Store = fs
		srv := NewServerWithExtra(d, Extra{Log: func(string, string, string) {}}, auth.Identity{OwnerID: e.owner})
		body, isErr := callParityResult(t, ctx, srv, "wait_for_updates", wait)
		return fs, body, isErr
	}
	fs, body, isErr := run("GetContact")
	if !fs.called["GetContact"] {
		t.Fatalf("never reached GetContact: %s", body)
	}
	if got := noStoreText(t, "wait_for_updates GetContact", body, isErr); got["code"] != "internal" || got["detail"] != refusal.InternalDetail {
		t.Errorf("wait_for_updates with GetContact failing: %s, want internal", body)
	}
	_, body, isErr = run("")
	var r waitResult
	if isErr || json.Unmarshal([]byte(body), &r) != nil || len(r.Calls) != 1 || r.Calls[0].ContactFpr != "sha256:k" || r.Calls[0].Trust != "messages_only" {
		t.Errorf("the control: want the held contact's call alone: %s", body)
	}
}

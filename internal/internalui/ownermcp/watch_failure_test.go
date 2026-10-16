package ownermcp

import (
	"context"
	"testing"
	"time"

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

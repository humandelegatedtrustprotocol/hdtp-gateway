package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func TestWriterExtendsPersistentChainAcrossRestart(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1756000000, 0)
	w := &Writer{Sink: st, Now: func() time.Time { return clock }}
	for i := 0; i < 5; i++ {
		if err := w.Append(ctx, "acct", "contact", "sha256:x", "tools/call", "tool:send_message", "ok", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	// "restart": a fresh writer must pick up the chain, not fork it
	w2 := &Writer{Sink: st, Now: func() time.Time { return clock }}
	if err := w2.Append(ctx, "acct", "owner", "o1", "settings_update", "account:acct", "ok", "", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListAuditEvents(ctx, "")
	if err != nil || len(rows) != 6 {
		t.Fatalf("rows: %v %d", err, len(rows))
	}
	events := make([]Event, 0, len(rows))
	for _, r := range rows {
		events = append(events, Event{
			Seq: r.Seq, TS: r.TS, AccountID: r.AccountID, ActorKind: r.ActorKind,
			ActorID: r.ActorID, Action: r.Action, Resource: r.Resource, Outcome: r.Outcome,
			RequestID: r.RequestID, Details: r.Details, PrevHash: r.PrevHash, Hash: r.Hash,
		})
	}
	if idx, err := Verify(events); err != nil {
		t.Fatalf("persistent chain broken at %d: %v", idx, err)
	}
	// filter by actor
	only, _ := st.ListAuditEvents(ctx, "o1")
	if len(only) != 1 || only[0].Action != "settings_update" {
		t.Fatalf("actor filter: %+v", only)
	}
}

package cli

import (
	"context"
	"io"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// serve's wipe (migration 0005, SEP-0006) writes one thread_id_wipe row per account that lost a
// conversation, with the counts and never the id, which is a contact's free text; an account that
// lost no conversation gets no row, and nothing is written when the wipe has run.
func TestServesWipeAuditsWhatWentPerAccount(t *testing.T) {
	n := newIDNode(t, "wipe")
	st := openStoreAt(t, n.dir)
	ctx := context.Background()
	lost, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "lost", DisplayName: "Lost", Algo: "p256"})
	whole, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "whole", DisplayName: "Whole", Algo: "p256"})
	for _, th := range []struct{ acct, id string }{{lost.ID, "a/b"}, {lost.ID, "kept1"}, {whole.ID, "kept2"}} {
		if err := st.InsertThread(ctx, store.Thread{ID: th.id, AccountID: th.acct, ContactFpr: "sha256:peer", CreatedAt: 1, LastAt: 1}); err != nil {
			t.Fatal(err)
		}
		if err := st.InsertMessage(ctx, store.Message{ID: "m" + th.id, AccountID: th.acct, ContactFpr: "sha256:peer", MsgID: "p" + th.id, ThreadID: th.id,
			Direction: "in", Sender: "agent", Kind: "text", Body: "hi", Status: "delivered", CreatedAt: 1}); err != nil {
			t.Fatal(err)
		}
	}
	// The other account's only row of neither form is a change row: it goes, and lost no
	// conversation, so it gets no audit row.
	if _, err := st.AppendChange(ctx, store.Change{AccountID: whole.ID, Kind: "message", ThreadID: "x.y", At: 1}); err != nil {
		t.Fatal(err)
	}
	var rows []string
	s := &serveRun{ctx: ctx, st: st, cfg: &core.Config{DataDir: n.dir}, stderr: io.Discard,
		auditFn: func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" "+outcome) }}
	if err := s.wipeThreadIDs(); err != nil {
		t.Fatal(err)
	}
	want := "thread_id_wipe account:" + lost.ID + " threads:1 messages:1 files:0 ok"
	if len(rows) != 1 || rows[0] != want {
		t.Fatalf("audit = %q, want [%q]", rows, want)
	}
	rows = nil
	if err := s.wipeThreadIDs(); err != nil || len(rows) != 0 {
		t.Fatalf("the second start: %v, rows %q", err, rows)
	}
}

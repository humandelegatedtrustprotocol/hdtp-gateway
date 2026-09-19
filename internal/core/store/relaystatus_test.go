package store_test

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/migrations"
)

// 0037 retires the delivery state a message was given when it was handed to a contact's
// store-and-forward relay. The role went with PACT 1.x and the state outlived it: nothing wrote it,
// the retry sweep never read it, and the portal went on saying "queued at their relay" about a
// relay that does not exist.
//
// What the migration has to get right is the ROW. A store that lived through 1.x can hold a message
// in that state; it was never confirmed delivered and never can be, so it becomes `failed` — and
// afterwards the state cannot be written at all. The fixture stops at version 36 rather than
// building the table by hand, so it cannot go stale when the schema next moves.
func TestAMessageLeftAtARelayIsMarkedFailedAndTheStateIsGone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lived-through-1x.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := fs.Sub(migrations.SQLite, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, raw, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 36); err != nil {
		t.Fatalf("migrating a fixture to version 36: %v", err)
	}
	// Raw SQL is a fixture's privilege; the code under test has none.
	for _, stmt := range []string{
		`INSERT INTO accounts (id, slug, display_name, algo, seal, status, created_at) VALUES ('acct', 'me', 'Me', 'ed25519', 'optional', 'active', 1)`,
		`INSERT INTO threads (id, account_id, contact_fpr, topic, created_at, last_at) VALUES ('t1', 'acct', 'sha256:p', '', 1, 1)`,
		`INSERT INTO messages (id, account_id, contact_fpr, msg_id, thread_id, direction, sender, body, status, created_at)
		 VALUES ('m-relay', 'acct', 'sha256:p', 'a', 't1', 'out', 'human', 'left at a relay', 'queued_at_relay', 10)`,
		`INSERT INTO messages (id, account_id, contact_fpr, msg_id, thread_id, direction, sender, body, status, created_at)
		 VALUES ('m-sent', 'acct', 'sha256:p', 'b', 't1', 'out', 'human', 'arrived', 'delivered', 11)`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	raw.Close()

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrating a store that lived through 1.x: %v", err)
	}
	msgs, err := st.ListMessagesByThread(ctx, "acct", "t1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range msgs {
		got[m.ID] = m.Status + ":" + m.Body
	}
	if got["m-relay"] != "failed:left at a relay" || got["m-sent"] != "delivered:arrived" || len(got) != 2 {
		t.Fatalf("the message left at a relay must read failed, whole, and nothing else may move: %v", got)
	}
	// And the state is gone from the schema, not merely from the rows.
	err = st.InsertMessage(ctx, store.Message{
		ID: "m-new", AccountID: "acct", ContactFpr: "sha256:p", MsgID: "c", ThreadID: "t1",
		Direction: "out", Sender: "human", Kind: "text", Body: "x", Status: "queued_at_relay", CreatedAt: 12,
	})
	if err == nil {
		t.Fatal("a message was written in the relay's delivery state after the migration that retired it")
	}
}

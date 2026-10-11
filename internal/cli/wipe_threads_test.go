package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/migrations"
)

// serve's wipe (migration 0005, SEP-0006) writes one thread_id_wipe row per account that lost a
// conversation, with the counts and never the id, which is a contact's free text; an account that
// lost no conversation gets no row, and nothing is written when the wipe has run.
func TestServesWipeAuditsWhatWentPerAccount(t *testing.T) {
	dir, _ := beforeTheWipe(t)
	st := openStoreAt(t, dir)
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
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
	s := &serveRun{ctx: ctx, st: st, cfg: &core.Config{DataDir: dir}, stderr: io.Discard,
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

// An offline command that migrates runs the wipe it schedules (migrateAndWipe): `migrate` on a store
// at migration 0004 deletes the thread of neither form and audits it, before any serve, so no
// export taken before the first start carries one; the thread of a form stays.
func TestMigrateRunsTheWipeItSchedules(t *testing.T) {
	dir, cfg := beforeTheWipe(t)
	ctx := context.Background()
	st := openStoreAt(t, dir)
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	for _, id := range []string{"a/b", "kept1"} {
		if err := st.InsertThread(ctx, store.Thread{ID: id, AccountID: a.ID, ContactFpr: "sha256:peer", CreatedAt: 1, LastAt: 1}); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	if code, out, errb := run(t, "migrate", "--config", cfg); code != 0 {
		t.Fatalf("migrate: %d %q %q", code, out, errb)
	}
	st = openStoreAt(t, dir)
	if _, err := st.GetThread(ctx, a.ID, "a/b"); err == nil {
		t.Fatal("migrate left the thread of neither form")
	}
	if _, err := st.GetThread(ctx, a.ID, "kept1"); err != nil {
		t.Fatalf("migrate took the thread of a form: %v", err)
	}
	rows, _ := st.ListAuditEvents(ctx, "")
	audited := false
	for _, r := range rows {
		audited = audited || (r.Action == "thread_id_wipe" && r.Resource == "account:"+a.ID+" threads:1 messages:0 files:0")
	}
	if !audited {
		t.Fatal("the wipe migrate ran is not audited")
	}
}

// beforeTheWipe is a node's data directory whose store is at migration 0004, before 0005 schedules
// the wipe, and its config file.
func beforeTheWipe(t *testing.T) (dir, cfg string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "old")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg = filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"data_dir":"`+dir+`","internal_bind":"127.0.0.1:0","public_bind":"127.0.0.1:0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := sql.Open("sqlite", filepath.Join(dir, "hdtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := fs.Sub(migrations.SQLite, "sqlite")
	p, err := goose.NewProvider(goose.DialectSQLite3, conn, sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 4); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	return dir, cfg
}

// export and import run the wipe with what it could not finish on their stderr: here a file of a
// wiped conversation whose directory refuses the deletion, told as "files not all collected", while
// the conversation itself is gone.
func TestAnExportsWipeTellsTheFilesItCouldNotCollect(t *testing.T) {
	dir, cfg := beforeTheWipe(t)
	ctx := context.Background()
	st := openStoreAt(t, dir)
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	blobs := messaging.BlobDir{Root: (&core.Config{DataDir: dir}).Blobs()}
	hash, err := blobs.Put([]byte("a file of a wiped conversation"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: hash, Size: 30, Mime: "text/plain", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(messaging.MediaMeta{Filename: "f.txt", Mime: "text/plain", Hash: hash})
	if err := st.InsertThread(ctx, store.Thread{ID: "a/b", AccountID: a.ID, ContactFpr: "sha256:peer", CreatedAt: 1, LastAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertMessage(ctx, store.Message{ID: "m1", AccountID: a.ID, ContactFpr: "sha256:peer", MsgID: "p1", ThreadID: "a/b",
		Direction: "in", Sender: "agent", Kind: "media", Body: string(body), Status: "delivered", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	held := filepath.Dir(filepath.Join(blobs.Root, hash[:2], hash))
	if _, err := blobs.Get(hash); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(held, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(held, 0o700) })
	_, _, errb := run(t, "export", "-config", cfg, "-slug", "me", "-out", filepath.Join(t.TempDir(), "me.zip"))
	if !strings.Contains(errb, `thread "a/b" deleted, its files not all collected`) {
		t.Fatalf("stderr does not tell the file it could not collect:\n%s", errb)
	}
	st = openStoreAt(t, dir)
	if _, err := st.GetThread(ctx, a.ID, "a/b"); err == nil {
		t.Fatal("the conversation was not wiped")
	}
}

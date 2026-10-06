package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/settings"
)

// A column that ties a row to an identity: every table with an account_id, and the tables that
// hang off an integration by its id.
type tieColumn struct{ table, column string }

// An identity leaving this host MUST leave no record of itself (HDTP §9): "delete every record of
// the identity". The tables are read from the MIGRATED SCHEMA, not from a list, so a table added
// later that names the account is covered the day it is added — and it fails here until the seed
// below writes a row into it, because a table the test never filled proves nothing.
//
// Two identities are seeded alike. The leaving one must be gone from every table but the audit
// trail (append-only by trigger: the leave does not reach it, and its rows go to the identity's
// archive later, once audit_archive_after has passed — internal/core/audit/departed_test.go);
// the one staying must keep every row it had — the control, without which a leave that erased
// everything would pass.
func TestSQLiteLeaveErasesEveryRowThatNamesTheIdentity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "leave.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	list := func(t *testing.T) []tieColumn {
		rows, err := db.QueryContext(ctx, `SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p
			WHERE m.type = 'table' AND p.name IN ('account_id', 'integration_id') ORDER BY m.name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []tieColumn
		for rows.Next() {
			var c tieColumn
			if err := rows.Scan(&c.table, &c.column); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return out
	}
	count := func(t *testing.T, table, column, value string) int64 {
		var n int64
		if err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %q WHERE %q = ?", table, column), value).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	leaveErasesEveryRow(t, st, list, count)
}

// The same on Postgres, where the pre-push hook provides one (HDTP_TEST_POSTGRES_DSN).
func TestPostgresLeaveErasesEveryRowThatNamesTheIdentity(t *testing.T) {
	dsn := os.Getenv("HDTP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("HDTP_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	const dbName = "hdtp_leave"
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	admin.Close(ctx)
	st, err := store.OpenPostgres(ctx, rewriteDB(dsn, dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, rewriteDB(dsn, dbName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	list := func(t *testing.T) []tieColumn {
		rows, err := conn.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND column_name IN ('account_id', 'integration_id') ORDER BY table_name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []tieColumn
		for rows.Next() {
			var c tieColumn
			if err := rows.Scan(&c.table, &c.column); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return out
	}
	count := func(t *testing.T, table, column, value string) int64 {
		var n int64
		if err := conn.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %q WHERE %q = $1", table, column), value).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	leaveErasesEveryRow(t, st, list, count)
}

type removedBlobs map[string]bool

func (r removedBlobs) Remove(hash string) error { r[hash] = true; return nil }

func leaveErasesEveryRow(t *testing.T, st store.Store, list func(*testing.T) []tieColumn, count func(t *testing.T, table, column, value string) int64) {
	ctx := context.Background()
	now := time.Now()
	o, err := st.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	day := int64(24 * 3600)
	var seq int64
	seed := func(slug string) (store.Account, string) {
		seq++
		a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: slug, DisplayName: slug, Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("seeding %s: %v", slug, err)
			}
		}
		must(st.AddMembership(ctx, o.ID, a.ID, "admin"))
		must(st.InsertToken(ctx, "tok-"+slug, o.ID, "t", []byte("hash-"+slug), a.ID, now.Unix()))
		_, err = st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:c-" + slug, Status: "active"})
		must(err)
		_, err = st.InsertInvite(ctx, store.Invite{AccountID: a.ID, TokenHash: []byte("inv-" + slug), ExpiresAt: 1 << 40, MaxUses: 1})
		must(err)
		must(st.InsertThread(ctx, store.Thread{ID: "th-" + slug, AccountID: a.ID, ContactFpr: "sha256:c-" + slug, CreatedAt: 1, LastAt: 1}))
		must(st.InsertMessage(ctx, store.Message{AccountID: a.ID, ContactFpr: "sha256:c-" + slug, MsgID: "m-" + slug, ThreadID: "th-" + slug,
			Direction: "in", Sender: "human", Kind: "text", Body: "hello", Status: "delivered", CreatedAt: 1}))
		must(st.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: "shared", Size: 1, CreatedAt: 1}))
		must(st.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: "only-" + slug, Size: 1, CreatedAt: 1}))
		in, err := st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://cal.example/mcp"})
		must(err)
		_, err = st.InsertCatalog(ctx, store.Catalog{IntegrationID: in.ID, Version: 1, Tools: "[]"})
		must(err)
		_, err = st.InsertExposure(ctx, store.Exposure{IntegrationID: in.ID, Version: 1, CatalogVersion: 1, Entries: "[]"})
		must(err)
		_, _, err = st.PutIdempotency(ctx, a.ID, "sha256:c-"+slug, "m-"+slug, "ack", now.Unix()+day)
		must(err)
		_, err = st.InsertPendingRequest(ctx, store.PendingRequest{AccountID: a.ID, ContactFpr: "sha256:c-" + slug, Capability: "x", Args: "{}", Status: "open", CreatedAt: 1, ExpiresAt: now.Unix() + day})
		must(err)
		must(st.UpsertMoveFanout(ctx, store.MoveFanout{AccountID: a.ID, ContactFpr: "sha256:c-" + slug, LeafKid: "k1-" + slug, Status: "done", UpdatedAt: 1}))
		// The ledger: a live current leaf, a live superseded one at the address it moved from, an
		// expired former one, and a pending request. The two live ones hold nothing after the leave.
		must(st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "k1-" + slug, Leaf: []byte{1}, KeySealed: []byte{9}, State: "current",
			NotBefore: now.Unix() - day, NotAfter: now.Unix() + 300*day, Endpoint: "https://new.example/a/" + slug + "/mcp", CreatedAt: 3}))
		must(st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "k0-" + slug, Leaf: []byte{1}, KeySealed: []byte{9}, State: "superseded",
			NotBefore: now.Unix() - 10*day, NotAfter: now.Unix() + 30*day, Endpoint: "https://old.example/a/" + slug + "/mcp", CreatedAt: 2}))
		must(st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "kx-" + slug, Leaf: []byte{1}, State: "former",
			NotBefore: now.Unix() - 400*day, NotAfter: now.Unix() - day, Endpoint: "https://gone.example/a/" + slug + "/mcp", CreatedAt: 1}))
		must(st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "kp-" + slug, KeySealed: []byte{9}, State: "pending",
			Endpoint: "https://next.example/a/" + slug + "/mcp", CreatedAt: 4}))
		must(st.UpsertTombstone(ctx, store.Tombstone{AccountID: a.ID, Root: "sha256:r-" + slug, Leaf: []byte{1}, At: 1}))
		must(st.InsertFormerEndpoint(ctx, store.FormerEndpoint{AccountID: a.ID, Root: "sha256:r-" + slug, Endpoint: "https://x.example/mcp", At: 1}))
		must(st.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: a.ID, Root: "sha256:r-" + slug, Endpoint: "https://x.example/mcp", Leaf: []byte{1}, Why: "moved", At: 1}))
		for _, k := range settings.AccountKeys(a.ID) {
			must(st.PutSetting(ctx, store.Setting{Key: k, Value: "1", UpdatedAt: 1}))
		}
		must(st.InsertAuditEvent(ctx, seq, 1, a.ID, "cli", "cli", "seed", "account:"+a.ID, "ok", "", "{}", "", "h-"+slug))
		_, err = st.AppendChange(ctx, store.Change{AccountID: a.ID, Kind: "message", ThreadID: "th-" + slug, At: 1})
		must(err)
		return a, in.ID
	}
	leaving, leavingIntegration := seed("leaving")
	staying, stayingIntegration := seed("staying")
	value := func(a store.Account, integration string, c tieColumn) string {
		if c.column == "integration_id" {
			return integration
		}
		return a.ID
	}

	cols := list(t)
	if len(cols) < 16 {
		t.Fatalf("the schema lists %d tables that name an identity; the query is looking at the wrong thing: %v", len(cols), cols)
	}
	for _, c := range cols {
		if count(t, c.table, c.column, value(leaving, leavingIntegration, c)) == 0 {
			t.Fatalf("%s.%s names an identity and the seed wrote no row into it: seed one, or this test proves nothing about it", c.table, c.column)
		}
	}

	blobs := removedBlobs{}
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "keyring"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	idm := &identity.Manager{Store: st, Keyring: kr}
	res, err := idm.Leave(ctx, leaving.ID, func(context.Context, store.Store) ([]string, error) { return settings.AccountKeys(leaving.ID), nil }, blobs.Remove)
	if err != nil {
		t.Fatalf("leave: %v", err)
	}

	for _, c := range cols {
		gone := count(t, c.table, c.column, value(leaving, leavingIntegration, c))
		kept := count(t, c.table, c.column, value(staying, stayingIntegration, c))
		if c.table == "audit_events" {
			if gone == 0 {
				t.Errorf("the audit trail lost the leaving identity's row: the leave must not reach it, only the archive does, after its period")
			}
		} else if gone != 0 {
			t.Errorf("%s still holds %d row(s) of the identity that left", c.table, gone)
		}
		if kept == 0 {
			t.Errorf("%s lost the rows of the identity that stayed", c.table)
		}
	}
	if _, err := st.GetAccountByID(ctx, leaving.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the account row is still there: %v", err)
	}
	if _, err := st.GetAccountByID(ctx, staying.ID); err != nil {
		t.Errorf("the staying account is gone: %v", err)
	}
	all, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range all {
		have[s.Key] = true
	}
	for _, k := range settings.AccountKeys(leaving.ID) {
		if have[k] {
			t.Errorf("setting %s outlived its identity", k)
		}
	}
	for _, k := range settings.AccountKeys(staying.ID) {
		if !have[k] {
			t.Errorf("setting %s of the staying identity was erased", k)
		}
	}
	if !blobs["only-leaving"] || blobs["shared"] || blobs["only-staying"] {
		t.Errorf("media removed %v, want only the file no other identity refers to", blobs)
	}
	if res.Leaves != 4 || res.BlobsRemoved != 1 {
		t.Errorf("result %+v", res)
	}

	// The address is free at once (HDTP §9, SEP-0002): every identity on this node is its one
	// operator's, so nothing holds the slug or the endpoint against the next one, while the two
	// leaves that named them are still live.
	if _, err := idm.IssueCSR(ctx, staying.ID, identity.PurposeMove, "https://new.example/a/leaving/mcp", now); err != nil {
		t.Fatalf("a signing request for the address the identity left was refused: %v", err)
	}
	if _, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "leaving", DisplayName: "Someone else", Algo: "p256"}); err != nil {
		t.Fatalf("the slug the identity left was refused to a new one: %v", err)
	}
}

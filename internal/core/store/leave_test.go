package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/services/settings"
)

// A column that ties a row to an identity: every table with an account_id, and the tables that
// hang off an integration by its id.
type tieColumn struct{ table, column string }

// An identity leaving this host MUST leave no record of itself (PACT §9): "delete every record of
// the identity". The tables are read from the MIGRATED SCHEMA, not from a list, so a table added
// later that names the account is covered the day it is added — and it fails here until the seed
// below writes a row into it, because a table the test never filled proves nothing.
//
// Two identities are seeded alike. The leaving one must be gone from every table but the audit
// trail (append-only by trigger: its rows keep the account id, and that is reported, not hidden);
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

// The same on Postgres, where the pre-push hook provides one (PACT_TEST_POSTGRES_DSN).
func TestPostgresLeaveErasesEveryRowThatNamesTheIdentity(t *testing.T) {
	dsn := os.Getenv("PACT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PACT_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	const dbName = "pact_leave"
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
		// expired former one, and a pending request. Only the two live ones reserve an address.
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
	res, err := idm.Leave(ctx, leaving.ID, func(context.Context, store.Store) ([]string, error) { return settings.AccountKeys(leaving.ID), nil }, blobs.Remove, now)
	if err != nil {
		t.Fatalf("leave: %v", err)
	}

	for _, c := range cols {
		gone := count(t, c.table, c.column, value(leaving, leavingIntegration, c))
		kept := count(t, c.table, c.column, value(staying, stayingIntegration, c))
		if c.table == "audit_events" {
			if gone == 0 {
				t.Errorf("the audit trail lost the leaving identity's row: it is append-only, and a leave must not reach it")
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

	// The addresses the two live leaves named are reserved until each one's notAfter; the expired
	// leaf's address and the pending request's are not.
	vac, err := st.ListVacatedAddresses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range vac {
		if v.Slug != "leaving" {
			t.Errorf("a reservation names slug %q", v.Slug)
		}
		got = append(got, v.Endpoint+fmt.Sprintf("@%d", v.UntilAt-now.Unix()))
	}
	sort.Strings(got)
	want := []string{fmt.Sprintf("https://new.example/a/leaving/mcp@%d", 300*day), fmt.Sprintf("https://old.example/a/leaving/mcp@%d", 30*day)}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("reserved %v, want %v", got, want)
	}

	// The slug is refused to a new identity while a reservation is live, at every door that makes
	// an account (they all reach the store's CreateAccount) ...
	if _, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "leaving", DisplayName: "Someone else", Algo: "p256"}); !errors.Is(err, store.ErrAddressVacated) {
		t.Fatalf("a new identity took the vacated slug: %v", err)
	}
	// ... and so is a signing request naming the address, from any identity.
	if _, err := idm.IssueCSR(ctx, staying.ID, identity.PurposeMove, "https://new.example/a/leaving/mcp", now); !errors.Is(err, store.ErrAddressVacated) {
		t.Fatalf("a signing request for the vacated address was made: %v", err)
	}
	// The control: a request for an address nobody left is made.
	if _, err := idm.IssueCSR(ctx, staying.ID, identity.PurposeMove, "https://elsewhere.example/a/staying/mcp", now); err != nil {
		t.Fatalf("a signing request for an ordinary address was refused: %v", err)
	}
	// Either side of the last notAfter, with a margin: reserved a minute before, free a minute after.
	last := now.Unix() + 300*day
	if live, _ := st.LiveVacatedSlug(ctx, "leaving", last-60); !live {
		t.Error("the slug was free a minute before its last leaf expires")
	}
	if live, _ := st.LiveVacatedSlug(ctx, "leaving", last+60); live {
		t.Error("the slug was still reserved a minute after its last leaf expired")
	}
	if live, _ := st.LiveVacatedEndpoint(ctx, "https://old.example/a/leaving/mcp", now.Unix()+30*day+60); live {
		t.Error("the old address was still reserved a minute after its leaf expired")
	}
	// The sweep drops only reservations that no longer reserve anything; once none is live, the
	// slug is an ordinary one again.
	if n, err := st.DeleteExpiredVacatedAddresses(ctx, now.Unix()+30*day+60); err != nil || n != 1 {
		t.Fatalf("sweep at the first expiry removed %d (%v), want the one expired", n, err)
	}
	if n, err := st.DeleteExpiredVacatedAddresses(ctx, last+60); err != nil || n != 1 {
		t.Fatalf("sweep at the last expiry removed %d (%v), want the last one", n, err)
	}
	if _, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "leaving", DisplayName: "Someone else", Algo: "p256"}); err != nil {
		t.Fatalf("the slug stayed refused with no reservation left: %v", err)
	}
}

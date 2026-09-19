package cli

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

// A person leaving the hosted platform takes a NODE-FORMAT store with them: pact-cloud's leave
// converter writes this module's own schema with goose bookkeeping "through 29" and hands it over
// data-only. That file is a contract between two repositories, and this one moved the schema five
// migrations past it in a day — 0030 dropped the relay tables, 0031 the rotation columns, 0032
// `accept_1x`, 0033 and 0034 the `protocol` columns. Every one of those is a column or table a
// version-29 store still HAS and still has values in.
//
// So the contract is: a store at exactly version 29, holding a 2.0 identity and a 2.0 pin the way
// the converter writes them, restores data-only on today's binary — migrated forward, keys
// stripped — and comes out as an identity that has a root and a contact that has a leaf.
func TestALeaveArchiveAtGoose29StillRestoresOnTodaysNode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "from-the-cloud.db")

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
	if _, err := p.UpTo(ctx, 29); err != nil {
		t.Fatalf("migrating a fixture to version 29: %v", err)
	}
	// As the converter writes them: protocol 2 on both, the root named on the account, the pin
	// carrying its endpoint, leaf and root certificate. `accept_1x` and the rotation columns take
	// their defaults, which is what a store that never used them holds.
	for _, stmt := range []string{
		`INSERT INTO accounts (id, slug, display_name, algo, seal, status, created_at, protocol, root_fingerprint, root_cert, accept_new_hosts)
		 VALUES ('acct', 'alina', 'Alina Rao', 'ed25519', 'required', 'active', 1, 2, 'sha256:alina-root', x'AA', 'ask')`,
		`INSERT INTO contacts (id, account_id, fingerprint, spki, status, preset, permissions, display_name, card, created_at, pinned_at, protocol, endpoint, leaf, chain_sent_kid, root_cert)
		 VALUES ('c1', 'acct', 'sha256:bharat-root', x'01', 'active', 'friend', '["message.text"]', 'Bharat', 'BEGIN:VCARD', 1, 1, 2, 'https://agent.bharat.example/mcp', x'1EAF', '', x'BB')`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	raw.Close()

	// The data-only path: migrate forward, then strip keys.
	if err := stripKeys(path); err != nil {
		t.Fatalf("a version-29 store from the cloud failed to restore: %v", err)
	}

	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, err := st.GetAccountBySlug(ctx, "alina")
	if err != nil {
		t.Fatalf("the identity did not survive the migration: %v", err)
	}
	if !a.HasRoot() || a.RootFingerprint != "sha256:alina-root" {
		t.Fatalf("the identity lost its root: %+v", a)
	}
	if a.AcceptNewHosts != "ask" {
		t.Fatalf("the owner's §5.3 choice did not survive: %q", a.AcceptNewHosts)
	}
	c, err := st.GetContact(ctx, a.ID, "sha256:bharat-root")
	if err != nil {
		t.Fatalf("the pin did not survive the migration: %v", err)
	}
	if c.Status != "active" || c.Endpoint != "https://agent.bharat.example/mcp" || len(c.Leaf) == 0 || len(c.RootCert) == 0 {
		t.Fatalf("the pin lost something on the way: %+v", c)
	}
}

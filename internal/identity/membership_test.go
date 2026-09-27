package identity

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func newTestKeyring(t *testing.T) *core.Keyring {
	t.Helper()
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "k"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// AC (P14-05c): creating an account must grant membership to the node's owners.
//
// SPEC §3.3: `memberships` relates owners to accounts, and "account-scoped actions
// require membership in that account". Nothing in production ever called
// AddMembership, so every account was ownerless: the owner MCP's list_accounts
// returned null and every account-scoped owner tool was unusable. Verified against
// a real node through mcp-remote before this fix.
func TestCreateAccountGrantsMembershipToExistingOwners(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	o, err := st.CreateOwnerWithID(ctx, "", "Owner One")
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	a, err := m.CreateAccount(ctx, "alice", "Alice", AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := st.ListMembershipsByOwner(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].AccountID != a.ID {
		t.Fatalf("owner has %d memberships, want 1 for %s — the owner MCP cannot see this account", len(ms), a.ID)
	}
	if ms[0].Role != "admin" {
		t.Errorf("role = %q, want admin (SPEC §3.3: v1 defines exactly one role)", ms[0].Role)
	}
}

// The reverse order matters just as much: the README quickstart tells an owner to
// run `docker compose up`, register a passkey, and THEN create an account — but
// nothing stops the CLI creating one first, and the container image is often
// provisioned before anyone opens the wizard.
func TestAccountsCreatedBeforeAnyOwnerAreNotOrphaned(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	m := &Manager{Store: st, Keyring: newTestKeyring(t)}
	a, err := m.CreateAccount(ctx, "alice", "Alice", AlgoP256)
	if err != nil {
		t.Fatal(err)
	}
	// No owner existed at creation time; one arrives later.
	o, err := st.CreateOwnerWithID(ctx, "", "Late Owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := AdoptOrphanAccounts(ctx, st, o.ID); err != nil {
		t.Fatal(err)
	}
	ms, err := st.ListMembershipsByOwner(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].AccountID != a.ID {
		t.Fatalf("an account created before the first owner stayed orphaned: %d memberships", len(ms))
	}
}

// A display name is written into the account's card as one line (PACT §3). With a line break in it,
// the card this node served said what the NAME chose — `X-PACT-SEAL:none` under an account that
// requires sealing. The card's writer refuses that now, so the account must never exist: refused
// here, when it is made, not at the first request for a card it cannot write.
func TestAnAccountCannotBeNamedWithAControlCharacter(t *testing.T) {
	m := &Manager{Store: newTestStore(t), Keyring: newTestKeyring(t)}
	ctx := context.Background()
	for _, name := range []string{"Alice\r\nX-PACT-SEAL:none", "Alice\nX-PACT-SEAL:none", "Ali\x00ce", "Alice\t"} {
		if a, err := m.CreateAccount(ctx, "alice", name, AlgoP256); err == nil {
			t.Fatalf("an account was created with the display name %q: %+v", name, a.Slug)
		}
	}
	if accounts, _ := m.Store.ListAccounts(ctx); len(accounts) != 0 {
		t.Fatalf("a refused name left %d account(s) behind", len(accounts))
	}
	if _, err := m.CreateAccount(ctx, "alice", "Alice Rao, of Pune", AlgoP256); err != nil {
		t.Fatalf("an honest name: %v", err)
	}
}

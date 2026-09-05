package identity

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
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

package identity

// Owner-to-account membership (SPEC §3.3).
//
// `memberships` relates owners to accounts, and "account-scoped actions require
// membership in that account" — so an account with no membership row is invisible
// to every owner surface. Nothing in production ever wrote one: the owner MCP's
// `list_accounts` returned null on every node, and every account-scoped owner tool
// was unusable. The gap was found by driving a real node's owner MCP through
// mcp-remote (P14-05c).
//
// v1 defines exactly one role, `admin`, and no `node_admin` flag exists on the
// owner record yet — so in v1 every owner administers the node. Membership is
// therefore granted in BOTH directions, because either object can be created
// first: the CLI can provision accounts before anyone opens the setup wizard, and
// the wizard can mint the first owner long after accounts exist.
//
// This grants an owner nothing they could not already take: creating an account
// requires the admin socket, which requires host shell access, which SPEC §3.1
// names as the node's recovery root of trust.

import (
	"context"
	"fmt"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// MembershipRoleAdmin is v1's only role (SPEC §3.3).
const MembershipRoleAdmin = "admin"

// grantToAllOwners gives every existing owner admin membership of one account.
func grantToAllOwners(ctx context.Context, st store.Store, accountID string) error {
	owners, err := st.ListOwners(ctx)
	if err != nil {
		return fmt.Errorf("identity: listing owners: %w", err)
	}
	for _, o := range owners {
		if err := st.AddMembership(ctx, o.ID, accountID, MembershipRoleAdmin); err != nil {
			return fmt.Errorf("identity: granting %s membership of %s: %w", o.ID, accountID, err)
		}
	}
	return nil
}

// AdoptOrphanAccounts gives one owner admin membership of every account that has
// none. Called when an owner is created, so accounts provisioned before the first
// passkey are not stranded — the order the README quickstart actually produces.
//
// It is idempotent: an account this owner already holds is skipped, so running it
// on every login is harmless.
func AdoptOrphanAccounts(ctx context.Context, st store.Store, ownerID string) error {
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return fmt.Errorf("identity: listing accounts: %w", err)
	}
	held := map[string]bool{}
	ms, err := st.ListMembershipsByOwner(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("identity: listing memberships: %w", err)
	}
	for _, m := range ms {
		held[m.AccountID] = true
	}
	for _, a := range accounts {
		if held[a.ID] {
			continue
		}
		if err := st.AddMembership(ctx, ownerID, a.ID, MembershipRoleAdmin); err != nil {
			return fmt.Errorf("identity: adopting account %s for owner %s: %w", a.ID, ownerID, err)
		}
	}
	return nil
}

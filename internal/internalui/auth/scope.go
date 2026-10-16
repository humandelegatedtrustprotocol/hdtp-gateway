package auth

import (
	"context"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Memberships is the node's store as policy.OwnerScope reads it: an owner's memberships, each its
// account and role. The portal and the owner MCP both decide an owner's scope through it.
type Memberships struct{ Store store.OwnerStore }

// OwnerMemberships lists the owner's memberships from the store.
func (m Memberships) OwnerMemberships(ctx context.Context, ownerID string) ([]policy.Membership, error) {
	ms, err := m.Store.ListMembershipsByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]policy.Membership, 0, len(ms))
	for _, x := range ms {
		out = append(out, policy.Membership{AccountID: x.AccountID, Role: x.Role})
	}
	return out, nil
}

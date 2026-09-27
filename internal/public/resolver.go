package public

import (
	"context"

	"github.com/pact-cloud/pact-gateway/internal/core/policy"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// StoreResolver builds the production CallerResolver: contact rows become policy
// callers — tier via TierFor, Blocked carried raw so Cedar's forbid fires
// (SPEC §3.5, §9.1).
func StoreResolver(st store.ContactStore) CallerResolver {
	return func(ctx context.Context, accountID, fpr string) (policy.Caller, error) {
		if fpr == "" {
			return policy.Caller{AccountID: accountID, Tier: policy.TierGuest}, nil
		}
		c, err := st.GetContact(ctx, accountID, fpr)
		if err != nil { // unknown = guest (PACT §6.1)
			return policy.Caller{AccountID: accountID, Fingerprint: fpr, Tier: policy.TierGuest}, nil
		}
		perms := map[string]bool{}
		for _, p := range c.Permissions {
			perms[p] = true
		}
		return policy.Caller{
			AccountID: accountID, Fingerprint: fpr,
			Tier:        policy.TierFor(c.Status, true),
			Permissions: perms,
			Blocked:     c.Status == "blocked",
		}, nil
	}
}

// Package policy is the single authorization call site (SPEC §3.6, §13.1).
// From P2-03 the engine is Cedar (cedar-go): the policy set below is STATIC and
// ships in the binary; everything owner- or contact-specific arrives as entity
// attributes built from store data at evaluation time. Callers never see Cedar —
// the Allow signature is the same one the interim engine had.
package policy

import (
	"fmt"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Tier is the surface a caller reaches, per HDTP §6.1: what a tool is offered at, and what a
// caller's relationship to the account entitles it to. A tool belongs to exactly one tier.
type Tier string

// The three tiers. A guest is a caller with no relationship, a blocked one, or one who asked us and
// awaits approval; pending is a peer the owner asked (pending_out), who may answer with
// contact_accepted or contact_rejected; contact is an active contact (TierFor).
const (
	TierGuest   Tier = "guest"
	TierPending Tier = "pending"
	TierContact Tier = "contact"
)

// Caller is the resolved caller context for one account.
type Caller struct {
	AccountID   string
	Fingerprint string // "" for anonymous guests
	Tier        Tier
	Permissions map[string]bool // granted dotted permissions (contact tier)
	Blocked     bool            // raw status==blocked: forbidden outright, over any permit
}

// Rule describes what a tool demands (SPEC §5.4 registry entry).
type Rule struct {
	Tier       Tier   // the exact surface the tool belongs to
	Permission string // dotted permission gating it; "" = always available at its tier
}

// The static policy set (SPEC §3.6): tiers are exact surfaces; permissions gate
// contact tools; a blocked principal is forbidden every tool ABOVE the guest
// surface regardless of any permit — Cedar's forbid-overrides-permit expresses
// §9.1's blocked semantics, and the guest exemption is what makes "blocked"
// indistinguishable from "never met" on the wire (SPEC §5.4, §9.1). Without it a
// blocked caller would see an empty tools/list where a stranger sees two, which
// is precisely the oracle the spec forbids. The forbid still matters: it is what
// stops a stale cached tier from serving contact tools to a blocked caller.
const policyText = `
permit (
  principal is Contact,
  action == Action::"call",
  resource is Tool
) when {
  principal.tier == resource.tier &&
  (!resource.gated || principal.permissions.contains(resource.permission))
};

forbid (
  principal is Contact,
  action,
  resource
) when { principal.blocked && resource.tier != "guest" };

permit (
  principal is Owner,
  action == Action::"manage",
  resource is Account
) when { principal.admin_accounts.contains(resource.id) };
`

var policies = func() *cedar.PolicySet {
	ps, err := cedar.NewPolicySetFromBytes("hdtp-static.cedar", []byte(policyText))
	if err != nil {
		panic(fmt.Sprintf("policy: static policy set invalid: %v", err))
	}
	return ps
}()

var callAction = types.NewEntityUID("Action", "call")
var manageAction = types.NewEntityUID("Action", "manage")

// Allow reports whether the caller may see and call a tool whose demands are r. It permits exactly
// when the caller's tier equals r.Tier and, if r.Permission is not empty, the caller holds that
// permission. A Blocked caller is refused every rule whose tier is not guest, whatever its tier or
// permissions. The decision is Cedar's over the static policy set; the diagnostics are discarded and the
// result is true exactly when Cedar's decision is Allow.
func Allow(c Caller, r Rule) bool {
	principalUID := types.NewEntityUID("Contact", types.String(callerID(c)))
	resourceUID := types.NewEntityUID("Tool", types.String(r.Tier)+"/"+types.String(r.Permission))

	perms := make([]types.Value, 0, len(c.Permissions))
	for p, ok := range c.Permissions {
		if ok {
			perms = append(perms, types.String(p))
		}
	}
	entities := types.EntityMap{
		principalUID: types.Entity{
			UID: principalUID,
			Attributes: types.NewRecord(types.RecordMap{
				"tier":        types.String(c.Tier),
				"blocked":     types.Boolean(c.Blocked),
				"permissions": types.NewSet(perms...),
			}),
		},
		resourceUID: types.Entity{
			UID: resourceUID,
			Attributes: types.NewRecord(types.RecordMap{
				"tier":       types.String(r.Tier),
				"gated":      types.Boolean(r.Permission != ""),
				"permission": types.String(r.Permission),
			}),
		},
	}
	decision, _ := cedar.Authorize(policies, entities, types.Request{
		Principal: principalUID, Action: callAction, Resource: resourceUID,
	})
	return decision == cedar.Allow
}

func callerID(c Caller) string {
	if c.Fingerprint == "" {
		return "anonymous@" + c.AccountID
	}
	return c.Fingerprint + "@" + c.AccountID
}

// OwnerCtx is an owner principal for internal-surface decisions (SPEC §3.3/§3.6):
// AdminAccounts lists the account ids where the owner holds the admin role.
type OwnerCtx struct {
	OwnerID       string
	AdminAccounts []string
}

// AllowOwnerManage reports whether the owner may manage accountID: true only when accountID is one
// of o.AdminAccounts. The decision is Cedar's over the static policy set.
func AllowOwnerManage(o OwnerCtx, accountID string) bool {
	principalUID := types.NewEntityUID("Owner", types.String(o.OwnerID))
	resourceUID := types.NewEntityUID("Account", types.String(accountID))
	accts := make([]types.Value, 0, len(o.AdminAccounts))
	for _, a := range o.AdminAccounts {
		accts = append(accts, types.String(a))
	}
	entities := types.EntityMap{
		principalUID: types.Entity{
			UID: principalUID,
			Attributes: types.NewRecord(types.RecordMap{
				"admin_accounts": types.NewSet(accts...),
			}),
		},
		resourceUID: types.Entity{
			UID: resourceUID,
			Attributes: types.NewRecord(types.RecordMap{
				"id": types.String(accountID),
			}),
		},
	}
	decision, _ := cedar.Authorize(policies, entities, types.Request{
		Principal: principalUID, Action: manageAction, Resource: resourceUID,
	})
	return decision == cedar.Allow
}

// TierFor maps a contact row's status to the caller tier (HDTP §6.1):
// absent/blocked → guest (silently indistinguishable), pending_out → pending
// (the peer we asked may call contact_accepted/rejected), active → contact.
// pending_in stays guest: someone who asked US gains nothing until approval.
func TierFor(status string, found bool) Tier {
	if !found {
		return TierGuest
	}
	switch status {
	case "active":
		return TierContact
	case "pending_out":
		return TierPending
	default: // blocked, pending_in
		return TierGuest
	}
}

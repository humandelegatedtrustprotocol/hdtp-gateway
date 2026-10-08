# internal/core/policy

The single authorization call site for what a caller may do on the public surface and what an owner may
manage (SPEC §3.6, §13.1). The engine is Cedar (`cedar-go`): the policy set is static, compiled into the
binary from the `policyText` constant, and everything specific to a caller or an owner arrives as entity
attributes built from the arguments at evaluation time. Callers never see Cedar.

It is rank 0 in the layer table (`internal/integrationtest/layering_test.go`): it imports no package of the
node, only `cedar-go`. Its callers are in `internal/public` (`public.StoreResolver` builds a `Caller` from a
contact row with `TierFor`; `servers.go` and `sealed.go` call `Allow` to build `tools/list` and to re-check
at call time, and `decide.go` and `identify.go` use `policy.Tier` as a type), `internal/internalui/ownermcp/server.go`
(`AllowOwnerManage`, with an `OwnerCtx` built from the owner's memberships) and `internal/cli`
(`integrationsurface.go` builds a `Rule`).

## What it holds

- `Tier`: `TierGuest`, `TierPending`, `TierContact`, the surface a caller reaches (HDTP §6.1). A tool belongs
  to exactly one tier; tiers are exact surfaces, not ranks, so a contact does not see guest tools.
- `Caller`: the resolved caller for one account: `AccountID`, `Fingerprint` (empty for an anonymous guest),
  `Tier`, `Permissions` (the granted dotted permissions) and `Blocked` (the contact's raw status was
  blocked).
- `Rule`: what a tool demands: the `Tier` it belongs to and the dotted `Permission` that gates it, or none.
- `Allow(Caller, Rule) bool`: the call decision. It permits when the caller's tier equals the rule's and,
  for a gated rule, the caller holds the permission.
- `TierFor(status, found) Tier`: a contact row's status to a tier. No row, `blocked` and `pending_in` are
  guest; `pending_out` is pending (the peer we asked may answer with `contact_accepted` or
  `contact_rejected`); `active` is contact.
- `OwnerCtx` and `AllowOwnerManage(OwnerCtx, accountID) bool`: whether an owner may manage an account,
  true only for an account in `AdminAccounts`.

The static policy set has three statements: a permit for a contact principal when the tool's tier equals the
principal's and the tool is ungated or the permission is held; a forbid for a blocked contact principal on
every tool whose tier is not guest; and a permit for an owner principal to `manage` an account in its
admin set.

## What it refuses, and how

`Allow` and `AllowOwnerManage` return `false`; there is no error value. The Cedar diagnostics are
discarded, and the result is true exactly when Cedar's decision is Allow. Specifically:

- a caller whose tier is not the rule's tier is refused;
- a gated rule is refused unless the caller holds the permission, and a caller with no permission map is
  refused every gated rule;
- a `Blocked` caller is refused every rule above the guest surface whatever its tier and permissions: the
  forbid overrides any permit. The guest surface is left alone on purpose, so a blocked caller is served
  exactly as a stranger is and `tools/list` cannot be used to tell the two apart (SPEC §5.4, §9.1);
- an owner is refused an account that is not in its `AdminAccounts`, and an owner with none is refused all.

## Invariants

- **Tiers are exact surfaces**, and a granted permission is exact too (`TestAllowExactTierAndPermission`).
- **Forbid overrides permit for a blocked caller, and a blocked caller sees exactly what an unknown one
  sees**: the test demotes a blocked contact with `TierFor("blocked", true)` and requires the two to agree
  rule by rule (`TestBlockedForbidOverridesEverything`).
- **`TierFor` maps every status** (`TestTierFor`).
- **An owner manages only its admin accounts** (`TestOwnerManageMatrix`).
- **A guest reaches the guest surface and nothing else** (`TestGuestScopeUnderCedar`).
- **The policy set is parsed once, in a package-level initializer, and a parse error panics** at start-up
  rather than becoming a decision.

## Held by

`policy_test.go`: `TestTierFor`, `TestAllowExactTierAndPermission`, `TestBlockedForbidOverridesEverything`,
`TestOwnerManageMatrix`, `TestGuestScopeUnderCedar`. The callers' own tests exercise it through
`internal/public` and the owner MCP.

## What it does not do

- It does not resolve a caller. `public.StoreResolver` reads the contact row and builds the `Caller`; it
  treats a caller with no row, and a failed lookup, as a guest.
- It does not know the tool registry. A `Rule` is handed to it by whoever registers the tool; that the
  registry's rules are right is the registry's to hold.
- It does not authenticate. The fingerprint in a `Caller` is whatever the identification step proved.
- It does not check that an `OwnerCtx` is genuine. `ownermcp` builds it from the owner's memberships, and
  `AllowOwnerManage` believes it.
- It does not audit a refusal. The caller that gets `false` decides what to write.

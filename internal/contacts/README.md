# contacts

The contact lifecycle of SPEC section 9 and HDTP sections 5 and 6, on the node's store. A guest
reaches the node through `internal/public` (and `internal/node` wires it): `Manager` turns a proven
call into a contact row (invite redemption, contact request, accept, reject, update, remove). The
owner reaches the same rows through `internal/internalui` (the portal), `internal/internalui/ownermcp`
and `internal/cli`, which all call `Owner`, so the surfaces cannot decide differently (owner.go:3-6).
Everything is written through `internal/core/store`; the package imports `internal/identity` only for
a test reference (manager.go:570) and `hdtp-identity/go` for card, certificate and address-guard
reading. `internal/services/settings`, `internal/services/retention`, `internal/integrationtest` and
`internal/storecheck` also import it (presets, cards, tests).

## What it holds

Inbound (manager.go, initiate.go):

- `Manager`, its `ContactCap` and `AdmitRequest` hooks, `Cap`, `Room`: the two caps. `Room` refuses
  with `ErrContactCap` (core.ErrContactCap) when `CountHeldContacts` is at the cap; the cap is
  `ContactCap()` when it returns more than 0, else `core.DefaultLimitContacts` (500, core/config.go:56).
- `CreateInvite`, `InviteOptions`, `MaxInviteTTL` (90 days), the default TTL (14 days, manager.go:37):
  a 16-byte random token returned once; only its SHA-256 is stored. A preset with no permission list
  grants that preset's bundle. `MaxUses` 0 is 1, negative is `1<<30`.
- `RedeemAs`, `RedeemResult`, `Proof`: guest-tier redemption. `Proof` is what the call proved (root
  fingerprint, leaf key, endpoint, leaf DER, and the optional address claim and root certificate); its
  zero value is refused.
- `RequestContactAs`: an unsolicited request, written `pending_in`.
- `AddressClaim`: the root of another contact pinned at an endpoint, or that held it within
  `hdtpidentity.ClaimWindow`.
- `ContactAccepted`, `ContactRejected`: a peer's answer to an approach of ours (`pending_out`).
- `Initiated`, `InitiatedByFingerprint`: record an approach the owner started, as `pending_out`.
- `UpdateContact`: refresh a contact's stored card. `RemoveContact`: a peer ends the relationship.
- `DecideAddress` (Manager): approve or reject a held move of a contact to a new address.

Owner side (owner.go): `Owner` with `Approve`, `Reject`, `Block`, `Unblock`, `Remove`,
`ExpireRequests`, `PendingAddresses`, `DecideAddress`; `Decision` (status after, grant, whether the
peer was told and why not); `AddressWaiting`; `Offered` (the permission rows a switchboard shows);
`NotifyBudget` (5 s per courtesy call to the peer) and `DefaultRequestExpiry` (30 days).

Presets and permissions (presets.go): `AllPermissions`, `DefaultPresets` (basic, work, friend, family),
`PresetSet` with `Names` and `Holds`, `LoadPresets` (rows `preset.*` in settings; the defaults when
none exist or the read fails), `ValidatePreset`, `ValidIntegrationSlug`, `TheirPermissions`.

Cards (vcard.go, card_facts.go): `BuildCard`, `ParseCard`, `ValidateInbound` (the one intake every
path uses; it reads the card with `hdtpidentity.DecodeCard`), `CardName`, `SealOf`, `Card`,
`MaxDisplayName` (64 runes), `CertificateUnreadable`, `CardUnreadableHint`, `CardFacts` and `FactsOf`.

### States and transitions

A contact row's status is one of `pending_in`, `pending_out`, `active`, `blocked`; no row is the state
`none`. `store.Contact.EverActive` records whether it was ever active (the store sets it on a move to
active, store.go:642). The transitions the code takes:

| From | To | By |
|---|---|---|
| none | pending_in | `RedeemAs` without auto-accept (or with an address claim), `RequestContactAs` |
| none | active | `RedeemAs` with auto-accept and no address claim (after `Room`) |
| none | pending_out | `Initiated`, `InitiatedByFingerprint` |
| pending_out | active | `ContactAccepted` (and `Initiated` when the peer already accepted) |
| pending_out | blocked | `ContactRejected` |
| pending_in | active | `Owner.Approve` (after `Room`; a named preset replaces the grant) |
| pending_in | blocked | `Owner.Reject` |
| any | blocked | `Owner.Block` |
| blocked | active | `Owner.Unblock` when `EverActive` (after `Room`) |
| blocked | none | `Owner.Unblock` when never active: the row is deleted |
| any | none | `Owner.Remove`, `Manager.RemoveContact` (both leave a tombstone when the row holds a leaf) |
| pending_in, pending_out | none | `Owner.ExpireRequests` (default 30 days) |

A pinned `pending_in` row redeeming an invite takes the invite's status, grant and label
(`RedeemOverPendingContact`, manager.go:318).

## What it refuses, and how

Wire codes are the package's sentinel errors (manager.go:24-29, owner.go:20):

- `invite_invalid`: unknown token, or expired, revoked or used up (checked before anything is spent,
  and again atomically by `ConsumeInviteUse`); the request was decided or the root inserted meanwhile.
- `identity_required`: a `Proof` without fingerprint or key; a card naming another root than the chain
  proved; a card whose certificate is not the proven leaf; in `Initiated`, a proven key that is not the
  card's leaf key.
- `bad_request`: an invite TTL over 90 days; a card that does not read; an endpoint the address guard
  refuses (loopback, link-local, private, or the node's own); a note over 1024 bytes; a card in
  `ContactAccepted`/`UpdateContact` naming another root; an unknown preset in `Approve`; a root already
  known in `RequestContactAs`, `Initiated`, `InitiatedByFingerprint`.
- `unknown_contact`: no such row, or not `pending_out` for `ContactAccepted`/`ContactRejected`.
- `conflict` (`ErrWrongState`): the row is not in a state the owner action applies to, or changed
  between the read and the guarded write (`moved`, owner.go:85).
- `ErrContactCap`: `Approve`, `Unblock` of an ever-active row, `RedeemAs` that would add an active row,
  and approving a new address for a root with no pin. `ErrRequestsFull` (`unavailable`): every write of a
  `pending_in` row; a `Manager` with no `AdmitRequest` writes no request at all (manager.go:73-78).
- A blocked caller is answered as a stranger: `RedeemAs` on a root held in any status except
  `pending_in` returns `Silent` and writes and spends nothing (manager.go:300-303).

## Invariants

- `pending_in` and `blocked` rows do not count against the contact cap; `active` and `pending_out` do
  (cap_test.go:31, `CountHeldContacts`).
- A use of an invite is spent only by a redemption that writes a row, in the same transaction.
- The pin is the root; the card must name that root and carry the proven leaf (`Proof.vet`).
- A card a peer pushes (`UpdateContact`) replaces the stored card but not the display name the owner
  approved (manager.go `UpdateContactCard(..., c.DisplayName)`).
- A permission list a peer reports is cut to `AllPermissions` plus `integration.<slug>`, each once
  (`TheirPermissions`); a peer's grant is stored as theirs, never as ours (`ContactAccepted`).
- Removal, by either side, tombstones a root that held a leaf, so a returning root with a newer leaf is
  asked about for 30 days (HDTP 5.3, manager.go tombstone comment). Approving the new address spends it.
- The owner's courtesy calls to a peer are bounded by `NotifyBudget` and never block the decision.

## Held by

- `TestSpecLifecycleDiagramIsWhatTheCodeDoes` (lifecycle_diagram_test.go): runs each owner/manager
  action on a real store and holds SPEC 9.1's mermaid diagram to the resulting edges and to the
  statuses the contacts table admits.
- `TestWhatCountsAgainstTheCap`, `TestApproveAndUnblockAreHeldToTheCap`,
  `TestARedemptionAtTheCapSpendsNothing`, `TestApprovingANewAddressIsHeldToTheCap` (cap_test.go).
- `TestTheRequestCapIsAskedBeforeEveryRequestIsWritten`, `TestAManagerWithoutTheCapWritesNoRequest`
  (pending_test.go).
- `TestAStrangerAtAPinnedContactsAddressIsNeverAutoAccepted`, `TestAddressClaimFollowsTheCoresRule`
  (claim_test.go); `TestRedeemByARootThisAccountAlreadyHolds` (redeem_known_test.go).
- `TestOwnerDecisionsWriteAgainstTheStatusTheyRead` (owner_race_test.go);
  `TestTheOwnersRemovalLeavesATombstone` (owner_remove_test.go).
- `TestACardRefreshCannotRenameAPinnedContact` (renamefreeze_test.go);
  `TestUpdateContactRefreshesTheCardAndNothingElse`, `TestACardThatDisagreesWithTheProofIsABadRequest`
  (manager_test.go).
- `TestInitiated*`, `TestAContactWeRequestedIsSealableOnceTheyAccept` (initiate_test.go).
- `TestTheirPermissionsAreFilteredAtIntake`, `TestAnAcceptanceRecordsOnlyWhatAGrantCanBe`
  (manager_review_test.go); `TestPresetsHolds`, `TestLoadPresetsResolution`, `TestValidatePreset`
  (presets_test.go).
- Card reading: `TestValidateInbound`, `TestIntakeReadsACardByTheCoreAlone`, `TestAPastedCardIsReadByTheCore`,
  `TestParsedNameIsCappedAndStripped`.

## What it does not do

- It does not sync contacts. A peer pushing its own refreshed card is `UpdateContact`; this package
  never calls a peer to fetch one. The calls that tell a peer of an owner decision (`TellApproved`,
  `TellRejected`, `TellRemoved`) are supplied by the caller and are best effort; nil means the peer is
  not told, and `Decision.Why` says so.
- `Block` is silent: the peer is told nothing (owner.go:195). `Reject` tells the peer.
- A card does not choose a contact's name after approval, and a display name is never made unique;
  telling two Alices apart is against the fingerprint (vcard.go `displayName` comment).
- `SealOf` of a contact with no card on file returns `required`; the SPEC does not say what a host
  assumes there (vcard.go, comment on `SealOf`).

# internal/identity

This package holds what the node has of an account's identity: the account's keypair (P-256 by default, Ed25519 permitted), the ledger of leaf certificates a wallet issued to this host and each leaf's key, the move campaign that tells contacts of a new address, and the erasure of an identity when its person leaves. The identity itself is the root, which the wallet holds; this host never holds the root's key. It is called by the CLI (`internal/cli`: `account.go`, `leafservice.go`, `serve.go`, `serve_admin.go`, `doctor.go`, `portablecmd.go`, `contactinit.go`, `ingresscmd.go`), the portal and owner MCP (`internal/internalui`, `internalui/ownermcp`, `internalui/auth`), the public door and the sealed-envelope path (`internal/public`: `sealed.go`, `decide.go`), the node (`internal/node`: `node.go`, `announce.go`, `campaign.go`, `refresh.go`, `outbound.go`), outbound calls (`internal/outbound`), ingress (`internal/ingress`), `internal/contacts`, `internal/portable` (import) and `internal/services/settings`. It calls `internal/core` (the keyring) and `internal/core/store` (accounts, leaves, contacts, `move_fanout`) and the identity library `hdtp-identity/go` for chain validation, CSRs and signature checks.

## What it holds

Keys and cards (`identity.go`, `manager.go`)
- `Algo`, `AlgoP256`, `AlgoEd25519`, `Keypair`, `Generate`, `Fingerprint`, `SelfSignedCert`, `MarshalPKCS8`, `ParsePKCS8`: key generation and encoding. `Keypair.HasChain` says the key is a certified leaf's.
- `VerifyCardSig`: the one reader of a card signature on this node (strict unpadded base64url, checked with the core's `VerifyDetached`).
- `Manager` (store plus node keyring), `ValidDisplayName`, `CreateAccount`, `LoadKeypair`, `SignCard`: account creation with a sealed key, and signing card text.
- `GrantToAllOwners`, `AdoptOrphanAccounts`, `MembershipRoleAdmin` (`membership.go`): owner-to-account membership; the only role is `admin`.

The leaf ledger (`leaf.go`, `walletreq.go`). A leaf row is in one of four states: `LeafPending` (a request made, the wallet has not answered; at most one per account), `LeafCurrent` (exactly one, the leaf the identity is served under), `LeafSuperseded` (replaced, key kept until its notAfter so an envelope sealed to it still opens), `LeafFormer` (key destroyed, kid kept so such an envelope is answered `certificate_renewed`).
- `IssueCSR`, `IssueWalletCSR`, `CSRResult`, `PurposeSignup`/`PurposeRenew`/`PurposeMove`: make the signing request. A renewal or move always mints a fresh key; a signup certifies the key the account was created with, or mints one when the host holds none (a data-only import).
- `InstallLeaf`, `InstallWalletLeaf`, `InstallResult`: install a wallet's answer. The web-wallet form also checks and consumes the request's `state`.
- `WalletPurpose`, `MoveNotice`: which purpose a web-wallet request carries (`move` or `renew`) and the sentence said after a move.
- `ActiveLeafKeypairs`, `ActiveLeafKeypairsFor`, `LeafKey`, `AdoptCurrentLeafKey`, `Chain`, `FormerKids`, `Certificate`, `CertificateInfo`, `RenewalWindow`: reads of the ledger.
- `RetireExpiredLeafKeys`, `RetiredLeaf`, `Warning`, `WarnUnscrubbed`: destruction of expired keys.
- `ToLib`, `PublicOf`, `FromLib`, `EndpointFor`: conversions and the account's address (`<public_url>/a/<slug>/mcp`).

The move campaign (`fanout.go`)
- `Campaign`, `CampaignFor`, `Campaign.Owes`, `Campaign.Walks`: who a leaf's campaign reaches. It owes the handshake to contacts an import left owed before the leaf was requested, and, if the leaf moved the identity, tells every active contact. A blocked contact is never walked.
- `Announcer`, `FanoutCall`, `Announcer.Fanout`, `FanoutRefused`, `FanoutUnreached`, `ErrFanoutIncomplete`: the durable walk. Progress is a `move_fanout` row per contact and leaf; a re-run skips contacts already done. A contact with no leaf held here is recorded `unreached` once and not called.
- `HandshakesOwed`, `HandshakesUnderWay`: the counts `account certificate` and `doctor` report.

Leaving (`leave.go`): `PreviewLeave`/`LeavePreview` read what would be erased; `Leave`/`LeaveResult` erase it.

## What it refuses, and how

- `IssueCSR`: an empty endpoint, an endpoint that is not an https URL in normal form (`IsNormalHTTPS`, leaf.go:429), an endpoint the core's `AddressGuard` refuses, such as a loopback, private or local host (leaf.go:436; returned as `ErrEndpointRefused` together with `ErrLeafRefused`), a renew or signup naming a different address than the current leaf's ("a move, so ask for one"), an unknown purpose. `IssueWalletCSR` refuses `signup` (with `ErrLeafRefused`) and an empty wallet origin.
- `InstallLeaf`/`InstallWalletLeaf`: no pending request (`ErrLeafRefused`; with a state, `ErrNoRequest` plus `ErrRequestState`); a state that is empty, already installed (`ErrRequestAnswered` plus `ErrRequestState`), or not the pending request's (`ErrRequestState`); a chain `ValidateChain` refuses (`ErrLeafRefused`, plus `ErrWrongRoot` when the root is another's); a leaf over another key than the request's (`ErrWrongKey`); a leaf not newer than the current one (`ErrNotNewer`). The state is judged before the chain, and is consumed only inside the install transaction, so a refused chain leaves the request answerable (leaf.go:740).
- `WalletPurpose`: an account with no root (`ErrLeafRefused`).
- `Chain`: `ErrNoCertificate` when the account has a root and no current leaf; nil, nil when it has no root.
- `SignCard`: an account with no key (an import, or an expired leaf) is refused with a message to install a leaf first (manager.go:140).
- `CreateAccount`: a display name with a control character, before any key is made.
- `Fanout`: `ErrFanoutIncomplete` when some contacts were not reached (a re-run resumes); a distinct error when progress could not be recorded.
- `Leave`: `store.ErrNotFound` when no account row was deleted; after the transaction commits, a failed scrub or media removal returns the result with an error saying the records are erased and N things were not finished.
- `VerifyCardSig`: a signature that is not strict unpadded base64url, an unreadable key, a signature that does not verify.

## Invariants

Standing rule 5, as this package enforces it.
- Leaf keys never leave the host: a key exists at rest only as PKCS#8 sealed by the node keyring, bound to its column by an AAD (`leaves.key_sealed`, leaf.go:31 and `accounts.key_sealed`, manager.go:38). Nothing in this package exports one; `LeafKey.PKCS8` and `.Lib` are in-memory forms for the inbound path.
- Keys are destroyed at expiry. `ActiveLeafKeypairsFor` does not serve a current or superseded leaf at or past its notAfter (leaf.go:195). `RetireExpiredLeafKeys` (leaf.go:283) destroys the key of every such leaf, the current one included, clearing the account's copy first (leaf.go:298) and then the ledger row's (leaf.go:302), keeps the kid, and scrubs the store (leaf.go:310). It runs on write paths, never on the read every inbound request takes. A renewal after expiry loses nothing, because `renew` always mints a fresh key (leaf.go:470-473).
- A leaf's lifetime is the wallet's choice. The only durations in this package are `RenewalWindow` (30 days: `Certificate` reports `RenewalDue` that far ahead of notAfter, leaf.go:51) and `SuggestedNotAfter`, 365 days after the request (leaf.go:518), which is a suggestion to the wallet. The installed leaf's own notAfter governs.
- An import ends with a new leaf, not a carried key. An account with a root and no key can serve nothing until the wallet certifies a key this host made: `SignCard` refuses it (manager.go:140), `IssueCSR` with `signup` mints a key when none is held (leaf.go:462), and `InstallLeaf` installs only a chain whose leaf carries the pending request's key (leaf.go:651). The import itself is in `internal/portable`.
- A leave erases the identity, and the keys with it, in one transaction (leave.go:90-131), then runs `Store.Scrub` so the deleted keys' bytes do not remain in the store's files (leave.go:138). Its address is free at once. Audit rows are not erased here.
- Single use and atomicity: the replacement of a pending request is one transaction under an account lock (leaf.go:499), the schema allows one pending row (`leaves_one_pending`), and the install is one transaction in which `ConsumeLeafRequest` lets exactly one of two simultaneous answers through.
- One rule for "moved": `moves` (walletreq.go:90) decides it for both the install (`InstallResult.Moved`, stored with the leaf) and `WalletPurpose`; `Campaign.Walks` is the one rule for who a campaign reaches. A re-run of `Fanout` resumes from `move_fanout` rows.
- There is no contact sync here. The only contact traffic is `Fanout`, which sends a handshake or new address to contacts for one leaf's campaign and is resumable; refreshing one contact on request is `internal/node/refresh.go`, not this package.

## Held by

All in this directory.
- `expiry_test.go`: `TestAnExpiredCurrentLeafLosesItsKeyInBothPlaces` (a live leaf is untouched; an expired one is not served by the read; the sweep destroys the key in the account row and the ledger row and keeps the kid).
- `keyscrub_test.go`: `TestALeaveLeavesNoLeafKeyOnDisk` and `TestARetiredLeafKeyIsNotLeftOnDisk` (the sealed key bytes are not found in the database file afterwards, after a control scan finds them while live).
- `leaf_test.go`: `TestLeafSignupThenRenewThenMove`, `TestInstallLeafRefusals`, `TestAFirstLeafOverAFreshKeyRetiresNothing`, `TestFirstLeafAfterADataOnlyImport`, `TestSignupMintsAKeyWhenTheHostHasNone`, `TestAnInstallOverAFormerLedgerKnowsWhetherItMoved`.
- `imported_root_test.go`: `TestAnImportedSlugHoldsOnlyItsRootUntilTheFirstChainInstalls`.
- `leafrace_test.go`: `TestConcurrentRequestsLeaveOnePending`, `TestTwoAnswersTogetherInstallOnce`, `TestARequestForAnAddressNoWalletCertifiesIsRefused`.
- `walletreq_test.go`: `TestAWebWalletsAnswerIsAcceptedOnceAndOnlyWithItsState`, `TestAWalletLeafNotNewerIsRefusedAsThat`, `TestTheStateIsConsumedByTheStatementThatChecksIt`, `TestWalletPurposeIsTheRuleTheInstallMovesBy`, `TestAMoveNoticeWithNoLedgerGivesNoDate`; `wallet_attack_test.go`: `TestAWalletAnswerCannotCrossIdentitiesOrEndpoints`.
- `fanout_test.go`: `TestTheCampaignWalksAnImportsContactsOnceAndNeverABlockedOne`, `TestTheCurrentLeafOwesTheHandshakeAnImportLeftBeforeItsRequest`, `TestAMoveCampaignSaysWhenItCannotRecordItsProgress`.
- `identity_test.go` (fingerprint, generation, PKCS#8 round trip, self-signed cert), `manager_test.go` (`TestManagerCreateAccountSealsAndBinds`, `TestSignCardRefusesWhenTheHostHoldsNoKey`), `membership_test.go` (membership in both directions, control characters in names).
- `Leave`'s erasure of settings, tokens, media and the audit trail is exercised in `internal/core/store/leave_test.go` (it calls `Leave` at line 228), not here; `PreviewLeave` has no test of its own in this directory.

## What it does not do

- It does not hold the root's key and cannot issue a leaf: a leaf comes from the wallet, in answer to a request this package makes.
- It does not rotate keys. A renewal is a new leaf over a new key; contacts learn it from the chain the next envelope carries (`fanout.go` header). Only a move needs a campaign.
- It does not write on the read path: `ActiveLeafKeypairs*`, `FormerKids` and `Certificate` never destroy a key; `RetireExpiredLeafKeys` does, and a key past notAfter is invisible to the read in the meantime.
- It does not tell contacts of a renewal at the same address. `Campaign.Walks` reaches every active contact only when the install decided `Moved`; otherwise only contacts an import left owed the handshake.
- It does not erase the audit trail, and a deleted key's bytes are cleared by `Scrub` only "where the engine allows it" (`Leave` doc; `WarnUnscrubbed` is the warning when the scrub did not finish).

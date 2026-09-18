# Conformance: PACT §12 → the tests that hold it up

This maps every clause of the PACT conformance checklist, every error code and
every documented limit to a test in this repository. It is checked
mechanically: `TestConformanceDocCitesRealTests` parses this file and fails the
build if it cites a test that does not exist, so the map cannot rot into
decoration.

Run the whole map with `make check`. Nothing here is aspirational — every row
names a test that passes today.

## The checklist

PACT §12: *"an implementation is a PACT agent server if it…"*

| Clause | Where it lives | Tests |
|---|---|---|
| exposes an MCP server over HTTPS accepting TLS client certificates | `internal/public/listener.go`, `internal/node` | `TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain`, `TestSNISelectsPerAccountIdentityCertificates`, `TestServeRunsTheWholeNode` |
| identifies callers by SPKI fingerprint against a contact list | `internal/identity`, `internal/public/identify.go` | `TestFingerprintMatchesOpenSSLFixture`, `TestFingerprintFormat` |
| guest / pending / contact tiers | `internal/core/policy`, `internal/public/servers.go` | `TestTierFor`, `TestAllowExactTierAndPermission`, `TestToolsListPerTier`, `TestBuiltinToolSurfacePerTier` |
| implements the guest and pending tools | `internal/public/tools.go` | `TestBuiltinToolSurfacePerTier`, `TestRedeemInvitePinsProvenKeyAndInvalidates`, `TestPendingAnswerTools` |
| implements `send_message` | `internal/public/tools.go`, `internal/messaging` | `TestSendMessageRecordsAndIsIdempotent`, `TestThreadIDSharedAcrossDirections` |
| implements `update_contact`, `remove_contact`, `get_card` (always available at contact tier) | `internal/public/tools.go`, `internal/contacts` | `TestAlwaysToolsAtContactTier`, `TestBuiltinToolSurfacePerTier` |
| filters `tools/list` per caller | `internal/public/servers.go` | `TestToolsListPerTier`, `TestPermissionFlipRebuildsAndNotifies`, `TestCallTimeDenyMidSession`, `TestGuestServersSharedAndCallerServersDistinct` |
| enforces manual approval for unsolicited requests | `internal/contacts/manager.go`, portal | `TestRedeemWithoutAutoAcceptIsPending`, `TestRequestContactNoteCapAndBinding`, `TestApproveAndRejectFlows` |
| invite issuance with expiry, uses and revocation | `internal/contacts/manager.go`, `internal/internalui` | `TestRedeemAutoAcceptYieldsActiveContact`, `TestRedeemFailures`, `TestInviteLifecyclePages` |
| emits and imports vCards with the `X-PACT-*` properties | `internal/contacts/vcard.go` | `TestForeignCardTolerated`, `TestCardPageAndVCFDownloadRoundTrip`, `FuzzVCardParse` |
| treats inbound strings as untrusted | `internal/public/tools.go`, `internal/messaging` | `TestBoundaryCapsRejectOversizedInput`, `TestTextCap`, `TestRequestContactNoteCapAndBinding`, `TestBodyCap` |
| honors idempotent `msg_id` | `internal/messaging/service.go`, `internal/public/sealed.go`, `internal/node/node.go` (`DeliverSealed` — the relay path, PACT §13.3) | `TestDuplicateMsgIDAcknowledgedNotReexecuted`, `TestSendMessageRecordsAndIsIdempotent`, `TestSealedReplayReturnsRecordedResult` |
| `msg_id` is scoped to the SENDER: the two directions are separate namespaces | `internal/messaging/service.go`, `migrations/*/0021_message_direction_key.sql` | `TestAnInboundMsgIDDoesNotSwallowAnOutboundMessage`, `MsgIDIsScopedToDirection` (both engines) |

PACT §12, sealed addendum: *"an implementation advertising `X-PACT-SEAL:
optional|required` additionally implements §13"*.

| Clause | Tests |
|---|---|
| `sealed_call` at every tier | `TestSealedCallIsPresentAtEveryTier`, `TestSealedGuestReachesGuestToolsOnly` |
| sealed results for sealed requests | `TestP1ExitTwoNodesPairAndMessage` |

## Error codes

Every code of PACT §12 (the 1.0 set plus the 1.1 delta) and the test that
produces it from the surface, not from a unit stub.

| Code | Tests |
|---|---|
| `unknown_contact` | `TestPendingAnswerTools`, `TestAlwaysToolsAtContactTier` |
| `pending_approval` | `TestBlockedCallerIsIndistinguishableFromAStranger` |
| `permission_denied` | `TestCallTimeDenyMidSession`, `TestSealedGuestReachesGuestToolsOnly`, `TestOwnerActionsAreAuditedAsOwner` (audited, per §5.8) |
| `invite_invalid` | `TestRedeemFailures`, `TestRedeemInvitePinsProvenKeyAndInvalidates` |
| `blocked_or_unknown` (guest catch-all, indistinguishable by design) | `TestBlockedCallerIsIndistinguishableFromAStranger`, `TestLandingNoOracle404` |
| `too_large` | `TestBoundaryCapsRejectOversizedInput`, `TestBodyCap`, `TestTextCap` |
| `rate_limited` (+ `retry_after`) | `TestContactRateLimit60PerHour`, `TestGuestRateLimit10PerHourPerIPAndKey`, `TestGuestRateLimitIsEnforcedOnTheRealListener` |
| `unavailable` (withheld capability or stale mapping) | `TestUnconfiguredCapabilityIsUnavailable`, `TestPickerShowsStaleAndReconfirmRestores` |
| `bad_request` | `TestSendMessageRecordsAndIsIdempotent`, `TestCalendarToolsRespectSlotCapAndBookIdempotently` |
| `seal_required` | `TestPlaintextToSealRequiredAccountRefused` |

## Limits

| Limit | Default | Tests |
|---|---|---|
| `text` | ≤16 KiB | `TestTextCap`, `TestBoundaryCapsRejectOversizedInput` |
| inline media | ≤5 MiB | `TestBoundaryCapsRejectOversizedInput`, `TestInlineStoresAndDedups` |
| `note` | ≤1 KiB | `TestRequestContactNoteCapAndBinding`, `TestBoundaryCapsRejectOversizedInput` |
| availability slots | ≤5 per response | `TestCalendarToolsRespectSlotCapAndBookIdempotently`, `TestP3ExitContactBooksCalendarSlot` |
| invite `expires_at` | ≤90 days | `TestRedeemFailures` |
| per-contact rate | 60 calls/hour | `TestContactRateLimit60PerHour` |
| guest rate | 10/hour per IP+key | `TestGuestRateLimit10PerHourPerIPAndKey` |
| request body (pre-parse) | 8 MiB | `TestBodyCap` |

## Beyond the checklist

PACT §12 is a floor. These hold up guarantees this implementation makes on top
of it, and are listed so a reader can tell the two apart.

| Guarantee | Tests |
|---|---|
| audit chain is append-only and tamper-evident | `TestVerifyDetectsSingleByteTamper`, `TestVerifyDetectsReorderAndDeletion`, `TestWriterExtendsPersistentChainAcrossRestart`, `TestAuditTamperedExportDetected` |
| a removed head is detected — verification is anchored, not self-rooted | `TestHeadTruncationIsDetected` |
| archiving prunes only what it captured, re-anchors, and keeps the chain verifiable across archive + live | `TestAuditArchivePrunesAndKeepsTheChainVerifiable` |
| session identity binding | `TestSessionIdCannotBeReplayedByAnotherIdentity`, `TestSessionBinding`, `TestSessionIsBoundToTheIdentityThatCreatedIt` |
| a session binding is reclaimed when the session ends without a DELETE, and a live one still cannot be re-bound | `TestAbandonedSessionBindingsAreReclaimed` |
| a withdrawn integration tool leaves sessions that are already open, repeatedly, and across LRU eviction | `TestWithholdingAnIntegrationWithdrawsItFromALiveSession`, `TestEvictionDoesNotOrphanALiveSession` |
| outbound retries are scheduled by attempts made, so uneven sweeps cannot starve a message | `TestRetriesStayOnScheduleWhenSweepsAreUneven`, `TestRetryBackoffWidensWithAge` |
| a sender-chosen `expires` survives the store on both engines | `MessageExpiryHoldsAFarFutureDeadline` (both engines) |
| the fallback chain runs at once when no owner agent is attached (§6.8) | `TestAgentAnsweredKnowsAboutPresenceFromConstruction`, `TestOwnerPresenceTracksLiveSessionsOnly` |
| `audit repair` refuses an archive whose rows were rewritten, rather than deleting the authentic copy | `TestRepairRefusesAnArchiveWhoseRowsWereRewritten`, `TestRepairRefusesWithoutItsArchiveFile` |
| the owner cannot be locked out by concurrent credential removal | `RemoveCredentialIfNotLastKeepsTheLastOne` (both engines) |
| a rollback of a POPULATED database does not fail half-way | `MigrateDownAndUpWithDataPresent` (both engines) |
| inbound URL media is never auto-fetched, private ranges refused | `TestPrivateRangeFetchRefusedAndAudited`, `TestFetchHappyPathWithInjectedRanges` |
| the portal auto-shows the wizard at zero passkeys (§8.3) | `TestPortalRootAutoShowsTheWizardAtZeroPasskeys` |
| the printed setup URL can host a WebAuthn ceremony (§12.4) | `TestSetupURLIsOneABrowserCanRegisterAgainst` |
| the setup wizard serves a real registration ceremony (§8.3) | `TestEmbeddedBundleCarriesTheCeremonies`, `TestWizardNonLoopbackNeedsToken` |
| the setup token survives the ceremony and dies on registration | `TestSetupTokenSurvivesRenderingTheWizard`, `TestWizardNonLoopbackNeedsToken` |
| a passkey can be registered and used through the portal, and the session gates it | `TestPortalRegistrationAndLoginCeremony` |
| only one owner can win a concurrent first registration | `TestConcurrentFirstRegistrationYieldsOneOwner` |
| a non-loopback portal refuses to start without a host passkeys can bind to | `TestNonLoopbackInternalNeedsAHost` |
| the portal requires a session on every bind, loopback included (§8.3); a spoofed Host cannot become the relying party | `TestLoopbackStillDemandsALoginAndHostIsNotTrusted` |
| an owner locked out of every passkey recovers with a minted token, and only with one (§3.1, §8.6) | `TestALockedOutOwnerCanRecoverWithAMintedToken` |
| an identity backup moves ONE account to a node with a different master key (§3.10) | `TestIdentityBackupMovesAnAccountToAnotherNode` |
| the backup is passphrase-sealed, refuses a wrong passphrase, and fails to open if its cleartext metadata is edited (§3.10) | `TestIdentityBackupRefusesAWrongPassphrase`, `TestEditingTheMetadataBreaksTheBackup` |
| restoring an identity refuses a collision rather than overwriting (§3.10) | `TestIdentityRestoreRefusesACollision` |
| the owner MCP exposes every tool SPEC §8.4 names, and still cannot register a passkey (§8.6) | `TestOwnerMCPHasTheSpecTools` |
| the dashboard reports the resolved posture, and the setup gate still owns the page until a passkey exists | `TestDashboardShowsStateAndKeepsTheWizardGate` |
| owner-MCP tokens are scoped and never leak | `TestTokenScopingAndUnknowns`, `TestTokenListNeverLeaksSecrets`, `TestServeOwnerMCPBearerGate`, `TestOwnersPageTokensAndPasskeys` |
| store behaves identically on SQLite and Postgres | `TestSQLiteConformance`, `TestPostgresConformance` |
| the LAN flag refuses private sources and audits it | `TestLANFlagOffRefusesDirectConnectionsAndAudits`, `TestLANGuardServesTheConnectorOnLoopback` |
| owner-set configuration persists, re-derives, and never overrides the environment | `TestSettingsPersistAcrossRestartAndReDerive`, `TestEnvPinnedKnobIsLockedAndUnwritable`, `TestRestartScopedSaveShowsAsPending`, `TestSQLiteConformance` |
| a saved credential is sealed at rest and never rendered or logged | `TestAdapterSecretIsSealedAndNeverRendered` |
| the card advertises exactly the seal policy the gate enforces, live — from **every** emitter (served, portal page, `/card.vcf`, key-rotation fan-out) | `TestSealChangeAppliesLiveAndCardMatchesTheGate`, `TestEveryCardEmitterAgreesWithTheServedCard`, `TestSetSealPersistsTheEffectiveValueNotTheRequestedOne` |
| a live `public_url` change reaches everything that renders it | `TestLandingLinkFollowsALivePublicURL`, `TestEveryCardEmitterAgreesWithTheServedCard` |
| every audit write carries an actor kind the store accepts | `TestAuditActorKindIsAlwaysWritable`, `TestOwnerActionsAreAuditedAsOwner` |
| every refusal is audited, and an availability failure is not recorded as a denial | `TestEveryRefusalIsAuditedAndAvailabilityIsNotADenial` |
| an undelivered message retries with backoff until its deadline (§7.1) | `TestOutboundExpiryDefaultsToTwentyFourHours`, `TestRetryBackoffWidensWithAge` |
| a contact's card cannot aim the send path at plaintext or an unverifiable address | `TestContactSuppliedEndpointsAreRefusedWhenUnsafe` |
| withholding an integration withdraws its tools from sessions already open (§6.5, §6.10) | `TestWithholdingAnIntegrationWithdrawsItFromALiveSession` |
| a repin keeps the pinned key when the call proved none | `TestSQLiteConformance` |
| the LAN flag is judged per request, so a live flip takes effect | `TestLANGuardDecidesPerRequestNotAtWiringTime` |
| ingress pairing works from the portal, and an unpaired ingress adapter cannot be selected | `TestIngressPairingFromThePortal`, `TestSelectingAnIngressAdapterWithoutPairingIsRefused` |
| the media quota is the documented one and is configurable per account | `TestDefaultQuotaMatchesTheSpec`, `TestStorageSettingsPersistAndApply`, `TestQuotaExceededError` |
| retention deletes past the window, keeps referenced blobs, and never deletes on a guess | `TestRetentionDeletesPastTheWindowAndKeepsLiveBlobs`, `TestUnlimitedRetentionDeletesNothing`, `TestSharedBlobBytesSurviveUntilTheLastReferenceGoes`, `TestUnreadableMediaBodyStopsBlobDeletion` |
| an interrupted archive is repairable, not reported as tampering (§11.6) | `TestInterruptedArchiveIsRepairableNotTampered`, `TestRepairRefusesWithoutItsArchiveFile` |
| the last passkey can never be removed, from any surface | `RemoveCredentialIfNotLastKeepsTheLastOne`, `TestSQLiteConformance`, `TestPostgresConformance` |
| the owner can read stored media, scoped to their account (§7.4, §8.2) | `TestOwnerCanReadStoredMediaButNotAnotherAccounts` |
| a contact's URL is fetched only when the owner asks (§7.5) | `TestMediaFetchIsOwnerInitiatedAndReportsRefusal`, `TestPrivateRangeFetchRefusedAndAudited` |
| `get_status` answers node-local status with no integration (§6.7) | `TestGetStatusAnswersWithoutAnyIntegration` |
| an agent-answered exposure parks a request naming its caller (§6.8) | `TestAgentAnsweredExposureParksARequest` |
| the portal consumes the SSE stream it serves (§8.1) | `TestPortalPagesConsumeTheEventStream` |
| owner-MCP revocation ends a live session (§3.4, §8.4) | `TestOwnerMCPRevocationEndsALiveSession` |
| the owner MCP requires a token on every bind (§8.3, §8.4) | `TestOwnerMCPRequiresATokenEvenOnLoopback` |
| integration management on the owner MCP shows exposure, not the catalog (§8.4) | `TestIntegrationToolsShowExposureNotTheUpstreamCatalog` |
| every owner-MCP call is audited, reads and refusals included (§8.7) | `TestEveryOwnerMCPCallIsAudited` |
| `pact://thread/<id>` signals one conversation (§8.5) | `TestSubscribeInboxReceivesResourceUpdated` |
| the front door drops rather than blocking when the terminator is gone | `TestFrontDoorDropsWhenTheTerminatorIsNotAccepting` |
| the messages rebuild preserves history and its constraints | `TestMessageTableRebuildPreservesHistory` |
| the data-plane vhost is internal, not publicly bound (§10.6) | `TestDataPlaneVhostDefaultsToLoopback` |
| one public port serves both ingress modes by SNI (§10.6) | `TestOnePortRoutesPassthroughAndTerminateBySNI`, `TestFrontDoorRefusesNonTLS` |
| a terminating ingress is pinned on the onward leg, as transport only (§10.6) | `TestTerminatingIngressIsPinnedOnTheOnwardLeg` |
| a terminate pairing announces its name for a certificate (§10.6) | `TestTerminatePairingAnnouncesItsNameForACertificate`, `TestACMEIssuanceAndRenewalWithPebble` |
| ingress pairings survive a restart (§10.6) | `TestPairingsSurviveARestart` |
| a pre-registered OAuth client is stored sealed (§6.3) | `TestOAuthClientRoundTripsSealed` |
| a static upstream credential is stored sealed and attached (§6.3, §11.3) | `TestStaticCredentialRoundTripsSealed` |
| capability resolution is cached, invalidated and TTL-bounded | `TestCapabilityResolutionIsCachedAndInvalidated` |
| a mapped exposure binds a core capability to a live upstream (§6.6, §6.7) | `TestMappedExposureBindsACoreCapability` |
| an exposure change through the owner MCP reaches a contact (§6.5, §8.4) | `TestExposureChangeThroughOwnerMCPReachesAContact` |
| a published exposure becomes a tool gated by `integration.<slug>` (§6, §6.6) | `TestPublishedExposureBecomesAPermittedTool` |
| a served tool group can be revised and withdrawn (§6.5, §6.10) | `TestRegistryGroupsAreRevisableAndAccountWideRebuildReachesOpenCallers` |
| the §6.5 stale guard runs without the owner clicking anything | `TestIntegrationChainIsWired`, `TestStaleGuardWithholdsAndReconfirmRestores` |
| the media quota applies without a restart (§7.4, §8.2) | `TestQuotaIsReadPerCallNotCapturedAtBuildTime`, `TestStorageSettingsPersistAndApply` |
| every demo doc carries a manual-run marker (GOAL item 6) | `TestDemoDocsCarryAManualRunMarker` |
| §11.2's tables and §12.1's commands match the code | `TestSpecTablesMatchTheCode` |
| config precedence is environment > file > store > defaults (§12.2) | `TestConfigFileOutranksOwnerSetSettings`, `TestSettingsPersistAcrossRestartAndReDerive` |
| the audit chain distinguishes owner actions from caller actions | `TestOwnerActionsAreAuditedAsOwner`, `TestAuditPageFiltersByActor` |
| `audit_query` never leaves the identity's accounts | `TestAuditQueryNeverLeavesTheIdentitysAccounts`, `TestScopedTokenCannotReadNodeLevelAuditRows` |
| owner-MCP tools cannot reach another account's integration | `TestSetExposureCannotReachAnotherAccountsIntegration` |

## PACT 2.0: the person is the certificate authority

The 2.0.0-draft (PACT §2, §3, §5.3, §9, §13.2, §14, Appendix C) on this node, on the
branch `pact-2.0-node`. The library the rules live in is `pact-identity/go`, proven
against Appendix B by its own tests; these are the node's.

| Clause | Where it lives | Tests |
|---|---|---|
| a leaf the wallet issued is installed only when it validates to the account's root, carries the requested key and is newer than the current one (§14.2, §14.3) | `internal/identity/leaf.go` | `TestLeafUpgradeThenRenewThenMove`, `TestInstallLeafRefusals` |
| a `v: 2` envelope is decided by the library and the effects applied: guest binding, both forms, tiers (§13.3, §6.1) | `internal/public/identify20.go` | `TestV2FirstContactMustRedeemOrRequest`, `TestV2PinnedContactBothForms` |
| a client-certificate chain resolves through the same pin rules as an envelope — superseded or blocked to guest, a new address by `accept_new_hosts`, a 1.x pin upgraded at the leaf's endpoint (§2, §5.3, §14.3). These are the node's OWN resolution, written against the library's rules rather than delegated to `Decide`, which is why they are their own row | `internal/public/identify20.go` (`ResolveTransport`) | `TestV2TransportPinChecks`, `TestPact20TransportChainResolvesThroughThePinChecks` |
| `chain_required` is one answer for unknown, blocked, expired and a bad signature, and spends the guest budget (§13.2, §14.5) | `internal/public/identify20.go`, `sealed.go` | `TestV2SmallFormUnknownBlockedAndBadSignatureAreOneAnswer` |
| a stale kid is answered `certificate_renewed` with the current chain, in plaintext (§14.4) | `internal/public/sealed.go` | `TestV2StaleKidIsAnsweredWithTheCurrentChain` |
| the newest leaf wins; a new address re-pins under `auto`, waits under `ask`, and a removed root returning is asked about (§14.3, §5.3) | `internal/public/identify20.go`, `internal/contacts/manager.go` | `TestV2NewestLeafWinsAndNewAddresses`, `TestV2TombstoneForcesTheQuestion` |
| a caller at an address the owner has not approved is told once however often it calls, and every such answer spends the guest budget (§5.3, §14.5) | `internal/public/identify20.go`, `sealed.go` | `TestV2AnUnapprovedAddressIsToldOnce` |
| the chain is the client certificate; a contact's chain as its server certificate validates to the pinned root at the dialed address; a 1.x pin of the leaf's key still connects (§2, Appendix C) | `internal/outbound/client.go` | `TestClientPresentsItsChain`, `TestChainAsServerCertificateValidatesToThePinnedRoot` |
| a 2.0 backup carries the leaf and never the root; a root key in the file is refused; another host's archive brings data only (§9) | `internal/identity/backup.go`, `internal/cli/backup.go` | `TestIdentityBackup20CarriesTheLeafAndNeverTheRoot`, `TestIdentityBackupRefusesARootKey`, `TestIdentityBackupMovesA20LeafToAnotherNode`, `TestRestoreRefusesAnotherHostsKeysUnlessDataOnly` |
| the exit demonstration: two nodes pair as 2.0 identities, message in both forms, one renews and the other learns the leaf from the answer and follows `certificate_renewed`, one moves and the other follows under `auto`; a 1.x node pairs with one and still talks after the renewal | `internal/node/pact20_demo_test.go` | `TestPact20ExitDemo` |

The live battery in `pact-cloud/gateway/conformance` gains a `certificate` group
built on the library alone — the card decodes, a stranger's small form is
`chain_required`, a stranger's full form may only redeem or request, a card to
another root is refused, a 2.0 contact pairs and speaks in the small form, a
superseded leaf is a guest, a move re-pins or waits, and a stale kid (when one
is named) is `certificate_renewed` — and skips itself against a 1.x card.

## Phase-exit demonstrations

| Phase | What it demonstrates | Test |
|---|---|---|
| P1 | two nodes pair and message, at `seal=optional` and `seal=required` | `TestP1ExitTwoNodesPairAndMessage` |
| P2 | browser pairing through the portal; an agent reads the inbox | `TestP2ExitPortalPairing` |
| P3 | a contact books a calendar slot through a mapped provider | `TestP3ExitContactBooksCalendarSlot` |
| P5 | own-domain ingress, passthrough and terminate | `TestP5ExitOwnDomainPassthroughAndTerminate` |
| P6 | the shipped binary serves all of it | `TestServeRunsTheWholeNode` |
| P7 | the owner can configure the node from the portal: reachability, security, relay, ingress pairing, storage, owners | `TestSettingsPersistAcrossRestartAndReDerive`, `TestIngressPairingFromThePortal`, `TestStorageSettingsPersistAndApply`, `TestOwnersPageTokensAndPasskeys`, `TestPortalRegistrationAndLoginCeremony` |
| P8 | the five fixed defects cannot silently regress | `TestSetSealPersistsTheEffectiveValueNotTheRequestedOne`, `TestEveryCardEmitterAgreesWithTheServedCard`, `TestAuditActorKindIsAlwaysWritable`, `TestEveryRefusalIsAuditedAndAvailabilityIsNotADenial`, `TestLANGuardDecidesPerRequestNotAtWiringTime` |

## Reachability

A cited test that passes proves the mechanism works. It does not prove the
shipped binary ever reaches it — and that gap is not theoretical: it is how five
tasks came to read `done` on the board while their product surface was never
wired. `TestEveryMechanismIsReachableFromTheShippedBinary` closes the two shapes
that actually occurred. Every package under `internal/` must be imported,
directly or transitively, by `cmd/pact-gateway`; and no exported `New*`
constructor may have callers only in tests, which is precisely how the rate
limiter and the session binder shipped — built, proven, named in the plan as
load-bearing, never installed. A third check covers exported **methods** with no
production caller, which is the shape most of this project's unwired machinery
actually takes.

It is a floor, not a proof. A function called only from another unreachable
function still reads as reached, a hook left `nil` in a composite literal is
invisible to all three checks, and the method check counts by bare name, so two
types sharing a method name share a counter. The floor sits where this project
has already fallen through.

Call sites inside **test-only packages** do not count as production references
either (P14-05d). `internal/core/store/conformance` is ordinary `.go` source — Go
compiles it as production — so its calls used to satisfy the gate. That hid a real
defect: `AddMembership` had no production caller at all, the owner MCP's
`list_accounts` returned `null` on every node, and this gate passed it because
`conformance.go` calls it twice. The table already excused that package from the
import check; its call sites needed excusing too.

The counter deliberately counts **uses, not declarations** (P12-12). Counting
every exported identifier made a declaration its own reference, so anything
declared more than once — every `Store` method is declared in the interface, in
both engine wrappers and in both generated `Queries` types — sat permanently
above any threshold the gate could set. The shape the gate most needed to catch
was the one it structurally could not. Sharpening it immediately surfaced an
unguarded `RemoveCredential` on the `Store` interface with zero callers: the twin
of the last-passkey guard without the guard, which has since been deleted rather
than excused.

Everything below is excused from that check. The table is self-cleaning: an
entry that becomes reachable fails the test just as loudly as a new violation,
so an exception cannot outlive the reason for it.

| Not reached | Why | Tracked by |
|---|---|---|
| `internal/integrationtest` | Test-only by construction: it assembles nodes and drives them, so nothing in production imports it. Its own reachability is not a meaningful question. | — |
| `internal/core/store/conformance` | The shared store-conformance suite both engines run. Test-only for the same reason. | — |
| `internal/testid` | Test-support by construction: it builds the roots, leaves and cards a 2.0 identity needs, so that nine test files across six packages do not each grow their own wallet. Nothing in production imports it. | — |

Method-level gaps. Four of these are Go interface dispatch — the runtime calls
them, no source names them — and the rest are debt with a task against it.

| Not reached | Why | Tracked by |
|---|---|---|
| `Envelope.UnmarshalJSON` | Interface dispatch: `encoding/json` calls it through `json.Unmarshaler`. No source can name it. | — |
| `Envelope.MarshalJSON` | The encode half of the wire codec whose decode half production does use. Nothing in the node encodes an envelope any more — the `v: 1` sealer and the relay were the callers, and both are gone — but a codec with one half deleted is worse than an unused method, and the tests that build envelopes need it. | — |
| `ownerUser.WebAuthnID` | Interface dispatch: `go-webauthn` calls it through `webauthn.User`. | — |
| `ownerUser.WebAuthnName` | Interface dispatch, as above. | — |
| `ownerUser.WebAuthnDisplayName` | Interface dispatch, as above. | — |
| `ownerUser.WebAuthnCredentials` | Interface dispatch, as above. | — |
| `Cloudflare.Point` | **Unwired, and not by the 1.x removal.** Nothing in this tree has ever called it: the ingress role's DNS pointer was built and never installed. Found by this gate on 2026-09-17 while the 1.x removal made the suite compile again. It needs wiring or deleting — it is excused here only so one pre-existing gap does not mask new ones. | unwired, needs a decision |
| `Manager.Ticking` | Test observability accessor on the integration health cycle. Deliberately not used in production. | — |
| `Server.WithFactsForTest` | Test seam onto the facts middleware, so a test can assert what a request is SEEN as rather than asserting on the flag that decides it — which is the difference between pinning behaviour and pinning a variable. | — |
| `ACME.Renew` | certmagic renews managed names on its own once `Manage` has been called; this forces one immediately and is exercised only by the renewal test. | — |
| `SQLite.MigrateDown` | A rollback seam on the `Store` interface, used by the conformance suite's `MigrateUpDownUp` and by the populated-rollback case (P14-03). SPEC §12.1 documents `migrate` as forward-only — there is deliberately no rollback command — so this has no production caller by design. | — |
| `SQLite.RemoveMembership` | v1 has no surface for editing account membership: it is granted automatically (P14-05c) and never revoked, because v1 defines one role and no multi-owner UX. Pre-shaped for post-v1 the same way the `role` column is. | post-v1 |
| `Queries.WithTx` | sqlc emits it for every generated `Queries` type. The `Store` interface exposes no transaction seam (100 methods, none transactional), so nothing can reach it; it is generated output, not written code. | P10 preplan, "the constraint shaping the atomicity work" |

## What is NOT covered by an automated test

Stated plainly, because a conformance document that hides its gaps is worse
than none:

- **Live third-party reachability.** Tailscale Funnel, a paid ngrok endpoint, a
  cloudflared tunnel and a real VPS front door are exercised against in-process
  or local stand-ins. The live runs are the dated manual checks in
  `docs/demos/*.md`.
- **A real Google Calendar.** `TestP3ExitContactBooksCalendarSlot` runs against
  a fake upstream speaking the recipe's tool names; the live run is
  `docs/demos/real-gcal.md`.
- **Browser rendering.** Portal pages are asserted as HTML, not screenshots.
- **Long-horizon behavior.** 30-day queue expiry, 90-day invite expiry and
  message retention windows are tested with an injected clock, never by waiting.
- **A real authenticator.** Passkey ceremonies run against a virtual
  authenticator (`descope/virtualwebauthn`), which exercises the protocol but not
  a physical security key or platform biometric prompt.
- **A live ingress.** Pairing is tested against an in-process `PairingServer`;
  the VPS run is `docs/demos/own-domain.md`.

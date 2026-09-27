# Conformance: PACT §12 → the tests that hold it up

This maps every clause of the PACT conformance checklist, every error code and
every documented limit to a test in this repository. It is checked
mechanically: `TestConformanceDocCitesRealTests` parses this file and fails the
build if it cites a test that does not exist, and
`TestConformanceDocLocationsExist` resolves every path, file and identifier the
"Where it lives" columns name, so the map cannot rot into decoration.

Run the whole map with `make check`. Nothing here is aspirational — every row
names a test that passes today.

## The checklist

PACT §12: *"an implementation is a PACT agent server if it…"*

| Clause | Where it lives | Tests |
|---|---|---|
| exposes an MCP server over HTTPS accepting TLS client certificates | `internal/public/listener.go`, `internal/node` | `TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain`, `TestSNISelectsPerAccountIdentityCertificates`, `TestServeRunsTheWholeNode` |
| identifies callers by fingerprint against a contact list — **the root of a validated chain** | `internal/public/listener.go`, `internal/public/decide.go` | `TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain`, `TestATransportChainResolvesThroughThePinChecks`, `TestV2PinnedContactBothForms`, `TestClientCertRequiredTakesAChainAndNothingElse` |
| the fingerprint itself is `"sha256:" + base64url(SHA-256(SPKI))` | `internal/identity` | `TestFingerprintMatchesOpenSSLFixture`, `TestFingerprintFormat` |
| guest / pending / contact tiers | `internal/core/policy`, `internal/public/servers.go` | `TestTierFor`, `TestAllowExactTierAndPermission`, `TestToolsListPerTier`, `TestBuiltinToolSurfacePerTier` |
| implements the guest and pending tools | `internal/public/tools.go` | `TestBuiltinToolSurfacePerTier`, `TestRedeemInvitePinsProvenKeyAndInvalidates`, `TestPendingAnswerTools` |
| implements `send_message` | `internal/public/tools.go`, `internal/messaging` | `TestSendMessageRecordsAndIsIdempotent`, `TestThreadIDSharedAcrossDirections` |
| implements `update_contact`, `remove_contact`, `get_card` (always available at contact tier) | `internal/public/tools.go`, `internal/contacts` | `TestAlwaysToolsAtContactTier`, `TestBuiltinToolSurfacePerTier` |
| filters `tools/list` per caller | `internal/public/servers.go` | `TestToolsListPerTier`, `TestPermissionFlipRebuildsAndNotifies`, `TestCallTimeDenyMidSession`, `TestGuestServersSharedAndCallerServersDistinct` |
| enforces manual approval for unsolicited requests | `internal/contacts/manager.go`, portal | `TestRedeemWithoutAutoAcceptIsPending`, `TestRequestContactNoteCapAndBinding`, `TestApproveAndRejectFlows` |
| invite issuance with expiry, uses and revocation | `internal/contacts/manager.go`, `internal/internalui` | `TestRedeemAutoAcceptYieldsActiveContact`, `TestRedeemFailures`, `TestInviteLifecyclePages` |
| the owner's side of the lifecycle (SPEC §9.1) is one implementation behind both surfaces: approval tells the peer the grant the row holds and reports when they could not be told; rejection demotes to blocked and tells the requester (`contact_rejected`); block is silent; unblock restores a row that was ever active and forgets one that never was; removal tells an active contact; each courtesy call is bounded | `internal/contacts/owner.go`, `internal/internalui/{manage,contacts}_pages.go`, `internal/internalui/ownermcp/server.go`, `internal/cli/contactinit.go` | `TestApproveTellsThePeerTheGrantTheRowHolds`, `TestApproveCarriesTheCouldNotBeToldNotice`, `TestApproveTellsThePeerWithinABudget`, `TestRejectTellsTheRequesterWithinABudget`, `TestBlockAndUnblockOnTheContactPage`, `TestApproveContactTellsTheRowsGrantWithinABudget`, `TestTheAgentRunsTheWholeContactLifecycle`, `EverActiveIsSetByEveryActivationAndClearedByNone` (both engines) |
| an unanswered request, theirs or ours, expires after the account's window (30 days by default) and is audited (SPEC §9.1) | `internal/services/retention/retention.go`, `internal/contacts/owner.go` | `TestTheSweepExpiresRequestsNobodyAnswered`, `DeleteExpiredPendingContactsTakesOnlyOldRequests` (both engines) |
| a blocked root holding a live invite link is answered what a stranger is, and spends and writes nothing; a waiting request that redeems a link is promoted, spending one use (PACT §12) | `internal/contacts/manager.go`, `internal/public/tools.go` | `TestRedeemByABlockedRootReadsAsAStrangersRedemption`, `TestRedeemByARootThisAccountAlreadyHolds`, `TestBlockedCallerIsIndistinguishableFromAStranger`, `RedeemOverPendingContactWritesOnlyAPendingRequest` (both engines) |
| every contact, request and invite decision a person can make in the portal, an agent can make over the owner MCP, and the reverse (SPEC §8.4); an invite is revoked only on its own account | `internal/internalui/parity_test.go` | `TestEveryAgentCapabilityHasAPortalAffordance`, `TestEveryContactAndInviteDecisionAPersonMakesAnAgentCanMake`, `TestTheAgentListsAndRevokesOnlyItsAccountsInvites`, `RevokeInviteIsScopedToItsAccount` (both engines) |
| `set_permissions` saves against the portal's switchboard: an integration the account serves or the contact holds is kept, any other name refused | `internal/contacts/owner.go` (`Offered`), `internal/internalui/ownermcp/server.go` | `TestSetPermissionsKeepsWhatTheSwitchboardOffersAndRefusesTheRest`, `TestSwitchboardOffersWhatTheNodeServes` |
| emits and imports vCards with the `X-PACT-*` properties | `internal/contacts/vcard.go` | `TestForeignCardTolerated`, `TestCardPageAndVCFDownloadRoundTrip`, `FuzzVCardParse` |
| treats inbound strings as untrusted | `internal/public/tools.go`, `internal/messaging` | `TestBoundaryCapsRejectOversizedInput`, `TestTextCap`, `TestRequestContactNoteCapAndBinding`, `TestBodyCap` |
| honors idempotent `msg_id` | `internal/messaging/service.go`, `internal/public/sealed.go` | `TestDuplicateMsgIDAcknowledgedNotReexecuted`, `TestSendMessageRecordsAndIsIdempotent`, `TestSealedReplayReturnsRecordedResult` |
| `msg_id` is scoped to the SENDER: the two directions are separate namespaces | `internal/messaging/service.go`, `migrations/*/0021_message_direction_key.sql` | `TestAnInboundMsgIDDoesNotSwallowAnOutboundMessage`, `MsgIDIsScopedToDirection` (both engines) |

PACT §12, sealed addendum: *"an implementation advertising `X-PACT-SEAL:
optional|required` additionally implements §13"*.

| Clause | Tests |
|---|---|
| `sealed_call` at every tier | `TestSealedCallIsPresentAtEveryTier`, `TestSealedGuestReachesGuestToolsOnly` |
| sealed results for sealed requests | `TestP1ExitTwoNodesPairAndMessage` |

## Error codes

Every code of PACT §12 and the test that produces it from the surface, not from a
unit stub.

This table used to say "the 1.0 set plus the 1.1 delta" and stop at
`seal_required`, which left the three codes 2.0 added with no row at all — while
`TestConformanceDocCitesRealTests` reported the map as sound, because it checks
that cited test names exist and cannot check that the list is complete.

| Code | Tests |
|---|---|
| `unknown_contact` | `TestPendingAnswerTools`, `TestAlwaysToolsAtContactTier` |
| `pending_approval` — plaintext before the envelope opens, **sealed** once it has (§13.2) | `TestBlockedCallerIsIndistinguishableFromAStranger`, `TestARefusalPastTheOpenIsSealed` |
| `permission_denied` | `TestCallTimeDenyMidSession`, `TestSealedGuestReachesGuestToolsOnly`, `TestOwnerActionsAreAuditedAsOwner` (audited, per §5.8) |
| `invite_invalid` | `TestRedeemFailures`, `TestRedeemInvitePinsProvenKeyAndInvalidates` |
| `blocked_or_unknown` (guest catch-all, indistinguishable by design) | `TestBlockedCallerIsIndistinguishableFromAStranger`, `TestLandingNoOracle404` |
| `too_large` | `TestBoundaryCapsRejectOversizedInput`, `TestBodyCap`, `TestTextCap` |
| `rate_limited` (+ `retry_after`) | `TestContactRateLimit60PerHour`, `TestGuestRateLimit10PerHourPerIPAndKey`, `TestGuestRateLimitIsEnforcedOnTheRealListener` |
| `unavailable` (withheld capability or stale mapping) | `TestUnconfiguredCapabilityIsUnavailable`, `TestPickerShowsStaleAndReconfirmRestores` |
| `bad_request` | `TestSendMessageRecordsAndIsIdempotent`, `TestCalendarToolsRespectSlotCapAndBookIdempotently` |
| `seal_required` | `TestPlaintextToSealRequiredAccountRefused` |
| `identity_required` | `TestEdgeModeSealedSucceedsPlaintextRefusedCertsIgnored`, `TestClientCertRequiredTakesAChainAndNothingElse` |
| `envelope_invalid` | `TestV2FirstContactMustRedeemOrRequest`, `TestAnEnvelopeMemberHasOneSpellingOnTheWire`, `TestAnUnreadableEnvelopeIsRefusedLikeAnyOther`, `FuzzSealedEnvelope`, and the whole intrusion battery (`pact vectors intrude`) |
| `chain_required` (2.0 — a small-form envelope the receiver cannot verify; one answer for unknown, blocked, expired and mis-signed alike) | `TestV2SmallFormUnknownBlockedAndBadSignatureAreOneAnswer` |
| `certificate_renewed` (2.0 — an envelope sealed to a leaf key this endpoint once held; the data carries the current chain) | `TestV2StaleKidIsAnsweredWithTheCurrentChain` |
| `seal_not_accepted` (a sealed call to a recipient whose card says `X-PACT-SEAL: none`) | `TestSealNoneRefusesEnvelopes`, `TestAnUnreadableEnvelopeIsRefusedLikeAnyOther` |

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
| configured internal TLS is served, a pair that does not load refuses the start by name, and the healthcheck reaches the TLS portal and accepts only its certificate (§8.3) | `TestTheInternalSurfaceIsServedOverTheConfiguredTLS`, `TestATLSConfigurationThatDoesNotLoadIsRefusedByName`, `TestServeRefusesATLSConfigurationThatDoesNotLoad`, `TestServeHonoursInternalTLSAndTheHealthcheckFollowsIt`, `TestTheHealthcheckAcceptsOnlyTheConfiguredCertificate`; live: S1 |
| the portal requires a session on every bind, loopback included (§8.3); a spoofed Host cannot become the relying party | `TestLoopbackStillDemandsALoginAndHostIsNotTrusted` |
| an owner locked out of every passkey recovers with a minted token, and only with one (§3.1, §8.6) | `TestALockedOutOwnerCanRecoverWithAMintedToken` |
| an export carries contacts and chats and nothing else: five kinds of line, no member but the manifest, the data and the media, and none of a host's secrets anywhere in its bytes (§3.10) | `TestAnExportCarriesContactsAndChatsAndNothingElse` |
| an import brings the identity by name, its contacts and its chats, and nothing of the old host's — no key, no ledger, no invite, no retry queue — on SQLite and Postgres alike (§3.10) | `TestAnImportBringsTheIdentityItsContactsAndItsChats` |
| an import refuses a key, an unknown kind, an unknown member, edited data, swapped media and a root certificate that is not the root it names — and writes nothing (§3.10, PACT §9) | `TestAnImportRefusesAnythingAnExportDoesNotCarry`, `TestAnImportDoesNotMergeIntoAnIdentityThatIsAlreadyHere` |
| an import is one transaction on both engines; a contact arrives with every column an export carries and none it does not (§3.10, §11.1) | store conformance: `AtomicallyLandsEverythingOrNothing`, `ImportContactWritesWhatAnExportCarries` |
| there is no `backup`, and neither export verb touches anything when typed bare (§12) | `TestTheExportVerbsCostNothingWhenTypedBare` |
| a lost master key costs a node its leaves and not the identity: a renewal under the same root installs, and the key it can no longer open is retired and reported (§3.10, PACT §14.4) | `TestALostMasterKeyCostsALeafNotTheIdentity`, `TestALostMasterKeyIsRecoveredByExportingAndImporting`, `TestAnAccountWhoseKeyWillNotOpenIsNamedNotHidden`, `TestServeNamesAnAccountWhoseKeyWillNotOpen`, `TestOneBrokenAccountStopsTheNodeOnlyWhenNothingProvesTheMasterKey` |
| the owner MCP exposes every tool SPEC §8.4 names, and still cannot register a passkey (§8.6) | `TestOwnerMCPHasTheSpecTools` |
| the dashboard reports the resolved posture, and the setup gate still owns the page until a passkey exists | `TestDashboardShowsStateAndKeepsTheWizardGate` |
| owner-MCP tokens are scoped and never leak | `TestTokenScopingAndUnknowns`, `TestTokenListNeverLeaksSecrets`, `TestServeOwnerMCPBearerGate`, `TestOwnersPageTokensAndPasskeys` |
| store behaves identically on SQLite and Postgres | `TestSQLiteConformance`, `TestPostgresConformance` |
| the LAN flag refuses private sources and audits it | `TestLANFlagOffRefusesDirectConnectionsAndAudits`, `TestLANGuardServesTheConnectorOnLoopback` |
| owner-set configuration persists, re-derives, and never overrides the environment | `TestSettingsPersistAcrossRestartAndReDerive`, `TestEnvPinnedKnobIsLockedAndUnwritable`, `TestRestartScopedSaveShowsAsPending`, `TestSQLiteConformance` |
| a saved credential is sealed at rest and never rendered or logged | `TestAdapterSecretIsSealedAndNeverRendered` |
| the card advertises exactly the seal policy the gate enforces, live — from **every** emitter (served, portal page, `/card.vcf`, the move campaign) | `TestSealChangeAppliesLiveAndCardMatchesTheGate`, `TestEveryCardEmitterAgreesWithTheServedCard`, `TestSetSealPersistsTheEffectiveValueNotTheRequestedOne` |
| a live `public_url` change reaches everything that renders it | `TestLandingLinkFollowsALivePublicURL`, `TestEveryCardEmitterAgreesWithTheServedCard` |
| a `public_url` change calls no contact — an address is inside a leaf, and a setting moves nobody — and names each account that now needs a move (§12) | `TestSavingANewPublicURLCallsNobodyAndNamesWhoMustMove` |
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

PACT 2.1 (§2, §3, §5.3, §9, §13.2, §14) on this node. The library the rules live in is
`github.com/pact-cloud/pact-identity/go` (the version `go.mod` requires), proven against
Appendix B by its own tests; these are the node's.

| Clause | Where it lives | Tests |
|---|---|---|
| a leaf the wallet issued is installed only when it validates to the account's root, carries the requested key and is newer than the current one (§14.2, §14.3) | `internal/identity/leaf.go` | `TestLeafUpgradeThenRenewThenMove`, `TestInstallLeafRefusals` |
| a `v: 2` envelope is decided by the library and the effects applied: guest binding, both forms, tiers (§13.3, §6.1) | `internal/public/decide.go` | `TestV2FirstContactMustRedeemOrRequest`, `TestV2PinnedContactBothForms` |
| a client-certificate chain resolves through the same pin rules as an envelope — superseded or blocked to guest, a new address by `accept_new_hosts` (§2, §5.3, §14.3). These are the node's OWN resolution, written against the library's rules rather than delegated to `Decide`, which is why they are their own row | `internal/public/decide.go` (`ResolveTransport`) | `TestV2TransportPinChecks`, `TestATransportChainResolvesThroughThePinChecks` |
| `chain_required` is one answer for unknown, blocked, expired and a bad signature, and spends the guest budget (§13.2, §14.5) | `internal/public/decide.go`, `sealed.go` | `TestV2SmallFormUnknownBlockedAndBadSignatureAreOneAnswer` |
| a stale kid is answered `certificate_renewed` with the current chain, in plaintext (§14.4) | `internal/public/sealed.go` | `TestV2StaleKidIsAnsweredWithTheCurrentChain` |
| the newest leaf wins; a new address re-pins under `auto`, waits under `ask`, and a removed root returning is asked about (§14.3, §5.3) | `internal/public/decide.go`, `internal/contacts/manager.go` | `TestV2NewestLeafWinsAndNewAddresses`, `TestV2TombstoneForcesTheQuestion` |
| a caller at an address the owner has not approved is told once however often it calls, and every such answer spends the guest budget (§5.3, §14.5) | `internal/public/decide.go`, `sealed.go` | `TestV2AnUnapprovedAddressIsToldOnce` |
| the chain is the client certificate; a contact's chain as its server certificate validates to the pinned root at the dialed address (§2, §14.2) | `internal/outbound/client.go` | `TestClientPresentsItsChain`, `TestChainAsServerCertificateValidatesToThePinnedRoot` |
| a pin is confirmed when it is needed and the node polls nobody: ONE contact's card is re-fetched, when its owner asks from that contact's page or the owner MCP's `refresh_contact`; an unanswered or refused refresh changes no pin, and a refresh can learn a renewed leaf and never a root or an address (§14.3) | `internal/node/refresh.go` | `TestNothingRefreshesContactsByItself`, `TestARefreshReachesOnlyTheContactThatWasNamed`, `TestAnUnansweredConfirmationChangesNoPin`, `TestVerifyRefreshedCard`, `TestARefreshLearnsARenewalAndNeverAnAddress`, `TestRefreshingOneContactOverTheWire` |
| what moves between hosts is data and never a key: the exporter holds none to write and the importer refuses one (§9) | `internal/portable/portable.go` | `TestAnExportCarriesContactsAndChatsAndNothingElse`, `TestAnImportRefusesAnythingAnExportDoesNotCarry` |
| a host accepts a web wallet's answer only once, only with the state it minted for a pending request, and only a chain whose leaf carries that request's key and validates at its endpoint; the signing request carries exactly the members a wallet takes (PACT §9.1) | `internal/identity/walletreq.go`, `internal/identity/leaf.go` (`InstallWalletLeaf`), `internal/cli/leafservice.go`, `internal/internalui/wallet_pages.go` | `TestAWebWalletsAnswerIsAcceptedOnceAndOnlyWithItsState`, `TestTheStateIsConsumedByTheStatementThatChecksIt`, `TestWalletPurposeIsTheRuleTheInstallMovesBy`, `TestTheWebWalletSigningRequestOnARunningNode`, `TestTheWalletReturnPageNeedsNoSessionAndHoldsNoData` |
| when the person leaves, the leaf keys and every record of the identity go at once and the address answers as one never served; an address the identity vacated is not assigned to another identity until the last leaf issued for it has expired (§9) | `internal/identity/leave.go`, `internal/core/store/{sqlite,postgres}.go` (`CreateAccount`), `internal/identity/leaf.go` (`IssueCSR`), `internal/cli/serve_admin.go` | `TestSQLiteLeaveErasesEveryRowThatNamesTheIdentity`, `TestPostgresLeaveErasesEveryRowThatNamesTheIdentity`, `TestAccountLeaveOnARunningNode`, `TestTheSweepDropsAReservationOnlyOnceItsLeafHasExpired` |
| after an import, the next leaf — a move or not — handshakes every imported contact that is not blocked: a peer that pins the root takes `update_contact`, one that refuses it is sent `request_contact` and decides under its own policy, each outcome is audited, a contact told is owed nothing more, and a contact whose leaf is not held is recorded `unreached` once, never called and counted apart (PACT §9.2) | `internal/identity/fanout.go`, `internal/node/announce.go`, `internal/node/request.go` | `TestAfterAnImportTheNextLeafHandshakesEveryImportedContact`, `TestTheCampaignWalksAnImportsContactsOnceAndNeverABlockedOne`; store conformance: `ImportContactWritesWhatAnExportCarries` |
| the exit demonstration: two nodes pair as 2.0 identities, message in both forms, one renews and the other learns the leaf from the answer and follows `certificate_renewed`, one moves and the other follows under `auto` | `internal/node/exit_demo_test.go` | `TestExitDemo` |

The live battery in `pact-cloud/gateway/conformance` gains a `certificate` group
built on the library alone — the card decodes, a stranger's small form is
`chain_required`, a stranger's full form may only redeem or request, a card to
another root is refused, a 2.0 contact pairs and speaks in the small form, a
superseded leaf is a guest, a move re-pins or waits, and a stale kid (when one
is named) is `certificate_renewed`. Against a node whose card is not a 2.0 card it FAILS; it
used to skip, when such a node was something that could exist.

## Phase-exit demonstrations

| Phase | What it demonstrates | Test |
|---|---|---|
| P1 | two nodes pair and message, at `seal=optional` and `seal=required` | `TestP1ExitTwoNodesPairAndMessage` |
| P2 | browser pairing through the portal; an agent reads the inbox | `TestP2ExitPortalPairing` |
| P3 | a contact books a calendar slot through a mapped provider | `TestP3ExitContactBooksCalendarSlot` |
| P5 | own-domain ingress, passthrough and terminate | `TestP5ExitOwnDomainPassthroughAndTerminate` |
| P6 | the shipped binary serves all of it | `TestServeRunsTheWholeNode` |
| P7 | the owner can configure the node from the portal: reachability, security, ingress pairing, storage, owners | `TestSettingsPersistAcrossRestartAndReDerive`, `TestIngressPairingFromThePortal`, `TestStorageSettingsPersistAndApply`, `TestOwnersPageTokensAndPasskeys`, `TestPortalRegistrationAndLoginCeremony` |
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
actually takes, and a fourth exported **functions** that are not constructors —
the review of 2026-09-23 found several at once (`CardKey`, `PresetHolds`,
`SealToken`, `catalog.Diff` among them), which no check here could see.

It is a floor, not a proof. A function called only from another unreachable
function still reads as reached, a hook left `nil` in a composite literal is
invisible to all four checks, and the counters count by bare name, so two
declarations sharing a name share a counter. The floor sits where this project
has already fallen through.

`make analyze` adds the whole-program check the floor is not:
golang.org/x/tools/cmd/deadcode, rooted at `cmd/pact-gateway`, which follows
calls rather than names and sees unexported functions too. Its report is held to
this same table by `TestDeadcodeFindsOnlyWhatTheTableExcuses` — a function it
finds must be excused here by its `Type.Method` or `pkg.Func`, or sit in an
excused package. The table's staleness stays with the hermetic gate, which is
why a row the deadcode report alone needs (`identity.FromLib`) must also be one
the fourth check needs.

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
| `ownerUser.WebAuthnID` | Interface dispatch: `go-webauthn` calls it through `webauthn.User`. | — |
| `ownerUser.WebAuthnName` | Interface dispatch, as above. | — |
| `ownerUser.WebAuthnDisplayName` | Interface dispatch, as above. | — |
| `ownerUser.WebAuthnCredentials` | Interface dispatch, as above. | — |
| `Server.WithFactsForTest` | Test seam onto the facts middleware, so a test can assert what a request is SEEN as rather than asserting on the flag that decides it — which is the difference between pinning behaviour and pinning a variable. | — |
| `identity.FromLib` | Called from another module: the cloud's conformance battery (`pact-cloud/gateway/conformance`) builds its reference peer's keypair through it, and `make dependents` is the gate that compiles that. A scan of this module alone reads it as unused; one such scan deleted it on 2026-09-19. | — |
| `SQLite.MigrateDown` | A rollback seam on the `Store` interface, used by the conformance suite's `MigrateUpDownUp` and by the populated-rollback case (P14-03). SPEC §12.1 documents `migrate` as forward-only — there is deliberately no rollback command — so this has no production caller by design. | — |
| `SQLite.RemoveMembership` | v1 has no surface for editing account membership: it is granted automatically (P14-05c) and never revoked, because v1 defines one role and no multi-owner UX. Pre-shaped for post-v1 the same way the `role` column is. | post-v1 |

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

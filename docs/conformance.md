# Conformance: HDTP §12 → the tests that hold it up

This maps every clause of the HDTP conformance checklist, every error code and
every documented limit to a test in this repository. It is checked
mechanically: `TestConformanceDocCitesRealTests` parses this file and fails the
build if it cites a test that does not exist, and
`TestConformanceDocLocationsExist` resolves every path, file and identifier the
"Where it lives" columns name, so the map cannot rot into decoration.

Run the whole map with `make check`. Nothing here is aspirational — every row
names a test that passes today.

## The checklist

HDTP §12: *"an implementation is an HDTP agent server if it…"*

| Clause | Where it lives | Tests |
|---|---|---|
| exposes an MCP server over HTTPS accepting TLS client certificates | `internal/public/listener.go`, `internal/node` | `TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain`, `TestSNISelectsPerAccountIdentityCertificates`, `TestServeRunsTheWholeNode` |
| identifies callers by fingerprint against a contact list — **the root of a validated chain** | `internal/public/listener.go`, `internal/public/decide.go` | `TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain`, `TestATransportChainResolvesThroughThePinChecks`, `TestPinnedContactBothForms`, `TestClientCertRequiredTakesAChainAndNothingElse` |
| the fingerprint itself is `"sha256:" + base64url(SHA-256(SPKI))` | `internal/identity` | `TestFingerprintMatchesOpenSSLFixture`, `TestFingerprintFormat` |
| guest / pending / contact tiers | `internal/core/policy`, `internal/public/servers.go` | `TestTierFor`, `TestAllowExactTierAndPermission`, `TestToolsListPerTier`, `TestBuiltinToolSurfacePerTier`, `TestThePendingTierIsRefusedPendingApproval` |
| implements the guest and pending tools | `internal/public/tools.go` | `TestBuiltinToolSurfacePerTier`, `TestRedeemInvitePinsProvenKeyAndInvalidates`, `TestPendingAnswerTools` |
| implements `send_message` | `internal/public/tools.go`, `internal/messaging` | `TestSendMessageRecordsAndIsIdempotent`, `TestThreadIDSharedAcrossDirections` |
| implements `update_contact`, `remove_contact`, `get_card` (always available at contact tier) | `internal/public/tools.go`, `internal/contacts` | `TestAlwaysToolsAtContactTier`, `TestBuiltinToolSurfacePerTier` |
| filters `tools/list` per caller | `internal/public/servers.go` | `TestToolsListPerTier`, `TestPermissionFlipIsServedToTheNextRequest`, `TestCallTimeDenyOnAServerComposedBeforeTheRevocation`, `TestGuestServersSharedAndCallerServersDistinct` |
| enforces manual approval for unsolicited requests | `internal/contacts/manager.go`, portal | `TestRedeemWithoutAutoAcceptIsPending`, `TestRequestContactNoteCapAndBinding`, `TestApproveAndRejectFlows` |
| invite issuance with expiry, uses and revocation | `internal/contacts/manager.go`, `internal/internalui` | `TestRedeemAutoAcceptYieldsActiveContact`, `TestRedeemFailures`, `TestInviteLifecyclePages` |
| the owner's side of the lifecycle (SPEC §9.1) is one implementation behind both surfaces: approval tells the peer the grant the row holds and reports when they could not be told; rejection demotes to blocked and tells the requester (`contact_rejected`); block is silent; unblock restores a row that was ever active and forgets one that never was; removal tells an active contact; each courtesy call is bounded | `internal/contacts/owner.go`, `internal/internalui/{manage,contacts}_pages.go`, `internal/internalui/ownermcp/server.go`, `internal/cli/contactinit.go` | `TestApproveTellsThePeerTheGrantTheRowHolds`, `TestApproveCarriesTheCouldNotBeToldNotice`, `TestApproveTellsThePeerWithinABudget`, `TestRejectTellsTheRequesterWithinABudget`, `TestBlockAndUnblockOnTheContactPage`, `TestApproveContactTellsTheRowsGrantWithinABudget`, `TestTheAgentRunsTheWholeContactLifecycle`, `EverActiveIsSetByEveryActivationAndClearedByNone` (both engines) |
| an unanswered request, theirs or ours, expires after the account's window (30 days by default) and is audited (SPEC §9.1) | `internal/services/retention/retention.go`, `internal/contacts/owner.go` | `TestTheSweepExpiresRequestsNobodyAnswered`, `DeleteExpiredPendingContactsTakesOnlyOldRequests` (both engines) |
| a blocked root holding a live invite link is answered what a stranger is, and spends and writes nothing; a waiting request that redeems a link is promoted, spending one use (HDTP §12) | `internal/contacts/manager.go`, `internal/public/tools.go` | `TestRedeemByABlockedRootReadsAsAStrangersRedemption`, `TestRedeemByARootThisAccountAlreadyHolds`, `TestBlockedCallerIsIndistinguishableFromAStranger`, `RedeemOverPendingContactWritesOnlyAPendingRequest` (both engines) |
| every contact, request and invite decision a person can make in the portal, an agent can make over the owner MCP, and the reverse (SPEC §8.4); an invite is revoked only on its own account | `internal/internalui/parity_test.go` | `TestEveryAgentCapabilityHasAPortalAffordance`, `TestEveryContactAndInviteDecisionAPersonMakesAnAgentCanMake`, `TestTheAgentListsAndRevokesOnlyItsAccountsInvites`, `RevokeInviteIsScopedToItsAccount` (both engines) |
| `set_permissions` saves against the portal's switchboard: an integration the account serves or the contact holds is kept, any other name refused | `internal/contacts/owner.go` (`Offered`), `internal/internalui/ownermcp/server.go` | `TestSetPermissionsKeepsWhatTheSwitchboardOffersAndRefusesTheRest`, `TestSwitchboardOffersWhatTheNodeServes` |
| emits and imports vCards with the `X-HDTP-*` properties | `internal/contacts/vcard.go` | `TestForeignCardTolerated`, `TestCardPageAndVCFDownloadRoundTrip`, `FuzzVCardParse` |
| treats inbound strings as untrusted | `internal/public/tools.go`, `internal/messaging` | `TestBoundaryCapsRejectOversizedInput`, `TestTextCap`, `TestRequestContactNoteCapAndBinding`, `TestBodyCap` |
| honors idempotent `msg_id` | `internal/messaging/service.go`, `internal/public/sealed.go` | `TestDuplicateMsgIDAcknowledgedNotReexecuted`, `TestSendMessageRecordsAndIsIdempotent`, `TestSealedReplayReturnsRecordedResult` |
| `msg_id` is scoped to the SENDER: the two directions are separate namespaces | `internal/messaging/service.go`, `migrations/*/0001_base.sql` | `TestAnInboundMsgIDDoesNotSwallowAnOutboundMessage`, `MsgIDIsScopedToDirection` (both engines) |

HDTP §12, sealed addendum: *"an implementation advertising `X-HDTP-SEAL:
optional|required` additionally implements §13"*.

| Clause | Tests |
|---|---|
| `sealed_call` at every tier | `TestSealedCallIsPresentAtEveryTier`, `TestSealedGuestReachesGuestToolsOnly` |
| sealed results for sealed requests | `TestP1ExitTwoNodesPairAndMessage` |
| a sealed answer is sealed under the recipient state its open read and reads none of its own: one read of that state for a sealed call that presents no client certificate — an answer, a refusal past the open, a budget's refusal (§13.2) | `TestASealedCallReadsTheRecipientStateOnce` |
| a card with no `X-HDTP-SEAL` line says `none`, and senders MUST NOT seal to it (§3, §13.4): the node reads a contact's policy off the card on file as the core reads a card, refuses to guess the policy of a card on file that does not read, and seals to a contact with no card on file (an import, or a returned root the owner approved: a gap the SPEC leaves, docs/release/port-parity-2026-09-29.md §3); the answer to a contact request goes to the asker the way its card says | `TestACardWithNoSealLineIsCalledInPlaintext`, `TestAContactsSealIsWhatItsCardOnFileSays`, `TestAnImportedContactWithNoCardOnFileCanBeWritten`, `TestAnAskerIsAnsweredTheWayItsCardSays` |
| an envelope's replay record is kept until `min(exp, ts + 300 s)` (§13.3): through the second `ts + 300`, which still passes the skew check, removed by the sweep after it, and never kept to a later `exp` | `TestAnEnvelopesReplayRecordIsKeptForTheWindowItCanBeAcceptedIn` |

## Error codes

Every code of HDTP §12 and the test that produces it from the surface, not from a
unit stub.

This table used to stop at
`seal_required`, which left three codes with no row at all — while
`TestConformanceDocCitesRealTests` reported the map as sound, because it checks
that cited test names exist and cannot check that the list is complete.

| Code | Tests |
|---|---|
| `unknown_contact` | `TestPendingAnswerTools`, `TestAlwaysToolsAtContactTier` |
| `pending_approval` — in plaintext to a plaintext call (a repeated request); **sealed** to a sealed one once the envelope has opened (§13.2): a root at an address not yet approved, and a `pending_out` contact calling before its answer, in either form, sealed to the leaf that signed | `TestBlockedCallerIsIndistinguishableFromAStranger`, `TestARefusalPastTheOpenIsSealed`, `TestAPendingContactsSealedCallIsAnsweredPendingApproval` |
| `permission_denied` | `TestCallTimeDenyOnAServerComposedBeforeTheRevocation`, `TestSealedGuestReachesGuestToolsOnly`, `TestOwnerActionsAreAuditedAsOwner` (audited, per §5.8) |
| `invite_invalid` | `TestRedeemFailures`, `TestRedeemInvitePinsProvenKeyAndInvalidates` |
| `blocked_or_unknown` (guest catch-all, indistinguishable by design) | `TestBlockedCallerIsIndistinguishableFromAStranger`, `TestLandingNoOracle404` |
| `too_large` | `TestBoundaryCapsRejectOversizedInput`, `TestBodyCap`, `TestTextCap` |
| `rate_limited` (+ `retry_after`; sealed as a tool error inside `result` once the envelope has opened) | `TestEveryKindOfChargeIsLetThroughFreshAndRefusedOnceSpentAndAnotherIdentityIsUntouched`, `TestARefusalPastTheOpenIsSealed`, `TestAPendingContactsSealedCallIsAnsweredPendingApproval`, `TestGuestRateLimitIsEnforcedOnTheRealListener` |
| `unavailable` (withheld capability or stale mapping) | `TestUnconfiguredCapabilityIsUnavailable`, `TestPickerShowsStaleAndReconfirmRestores` |
| `bad_request` | `TestSendMessageRecordsAndIsIdempotent`, `TestCalendarToolsRespectSlotCapAndBookIdempotently` |
| `seal_required` | `TestPlaintextToSealRequiredAccountRefused` |
| `identity_required` | `TestEdgeModeSealedSucceedsPlaintextRefusedCertsIgnored`, `TestClientCertRequiredTakesAChainAndNothingElse` |
| `envelope_invalid` | `TestFirstContactMustRedeemOrRequest`, `TestAnEnvelopeMemberHasOneSpellingOnTheWire`, `TestAnUnreadableEnvelopeIsRefusedLikeAnyOther`, `FuzzSealedEnvelope`, and the whole intrusion battery (`hdtp vectors intrude`) |
| `chain_required` (a small-form envelope the receiver cannot verify; one answer for unknown, blocked, expired and mis-signed alike) | `TestSmallFormUnknownBlockedAndBadSignatureAreOneAnswer` |
| `certificate_renewed` (an envelope sealed to a leaf key this endpoint once held; the data carries the current chain) | `TestStaleKidIsAnsweredWithTheCurrentChain` |
| `seal_not_accepted` (a sealed call to a recipient whose card says `X-HDTP-SEAL: none`) | `TestSealNoneRefusesEnvelopes`, `TestAnUnreadableEnvelopeIsRefusedLikeAnyOther` |

## Limits

The call budgets' numbers are the limits sidecar's configuration (`deploy/limitd/limits.json` as shipped; members named below), and the arithmetic is hdtp-identity's `hdtp-limits` crate, which is held to the cloud's by `js/cases/limits-vectors.json` in that repository.

| Limit | Default | Tests |
|---|---|---|
| `text` | ≤16 KiB | `TestTextCap`, `TestBoundaryCapsRejectOversizedInput` |
| inline media | ≤5 MiB | `TestBoundaryCapsRejectOversizedInput`, `TestInlineStoresAndDedups` |
| `note` | ≤1 KiB | `TestRequestContactNoteCapAndBinding`, `TestBoundaryCapsRejectOversizedInput` |
| availability slots | ≤5 per response | `TestCalendarToolsRespectSlotCapAndBookIdempotently`, `TestP3ExitContactBooksCalendarSlot` |
| invite `expires_at` | ≤90 days | `TestRedeemFailures` |
| per-contact rate | `contact_calls_per_second`, burst `contact_burst` | `TestEveryKindOfChargeIsLetThroughFreshAndRefusedOnceSpentAndAnotherIdentityIsUntouched`, `TestASealedContactIsNotBudgetedAsAGuest` |
| per-account rate | `limit.contacts` × `contact_calls_per_second`, burst one second of it, at most `identity_capacity_per_second` | `TestEveryKindOfChargeIsLetThroughFreshAndRefusedOnceSpentAndAnotherIdentityIsUntouched`, `TestTheCardIsTheRulesAndTheCratesAggregate` |
| guest rate | `guest_calls_per_hour`, per root and address | `TestEveryKindOfChargeIsLetThroughFreshAndRefusedOnceSpentAndAnotherIdentityIsUntouched`, `TestASealedContactIsNotBudgetedAsAGuest` |
| source rate (no root proven) | `guest_source_calls_per_hour`, per address | `TestGuestRateLimitIsEnforcedOnTheRealListener` |
| calls out | to a contact its rate and the aggregate; to anybody else `stranger_calls_out_per_hour` | `TestTheNodesCallsOutAreBudgeted` |
| requests waiting on the owner | `pending_in_cap`, refused `unavailable` | `TestTheRequestCapIsAskedBeforeEveryRequestIsWritten`, `TestAStrangersRequestIsHeldToTheSidecarsPendingCap` |
| one integration, per contact | `integration_calls_per_hour` | `TestAnIntegrationsCallsAreHeldToItsOwnCapPerContact` |
| the guest total | `guest_total_calls_per_hour`, every caller the open does not prove a contact; checked before the open, where only a known address gets past it once spent, and spent after it, all or none with the caller's own buckets | `TestAStrangerFloodDrainsTheTotalThenIsRefusedBeforeTheOpenAndAKnownContactGetsThrough`, `TestSmallFormsNamingLeavesNobodyPinnedDrainTheTotalAndAreThenRefusedBeforeTheOpen`, `TestACallTheTotalRefusesBeforeTheOpenReadsNoKeyAndOpensNothing`, `TestAnOpenedCallThatProvesNobodyIsChargedTheTotal`, `TestASealedContactIsNotBudgetedAsAGuest`, `TestTheGuestTotalIsSpentWithTheGuestAndAskedBeforeTheOpenWithoutSpending` |
| the limits sidecar not answering | every call it would decide refused `unavailable`; `/healthz` 503, `doctor`, the banner and the sidecar container's own healthcheck (`healthcheck --limits`) name it | `TestEveryBudgetIsRefusedUnavailableWhileTheSidecarIsDown`, `TestABudgetThatCannotBeAskedRefusesUnavailable`, `TestASidecarThatIsDownIsNamedByTheHealthCheckDoctorAndTheBanner`, `TestTheHealthcheckOfTheSidecarAsksItsSocketAndNoPortal` |
| what spends | every inner call that reaches dispatch; a replay does not | `TestEveryInnerCallSpendsAndAReplayDoesNot`, `TestARefusedCallIsNotRecordedAsTheAnswer` |
| advertised `limits` | the sidecar's rules and its aggregate for the account | `TestTheCardIsTheRulesAndTheCratesAggregate`, `TestGetCardAdvertisesTheLimitsInForce` |
| request body (pre-parse) | 8 MiB, refused `too_large` by the bytes that arrive | `TestBodyCap`; on the running listener `TestBodiesPastTheCapAreRefusedByTheBytesThatArrive` (a body of exactly 8 MiB answered, one byte more refused) |

## Beyond the checklist

HDTP §12 is a floor. These hold up guarantees this implementation makes on top
of it, and are listed so a reader can tell the two apart.

| Guarantee | Tests |
|---|---|
| audit chain is append-only and tamper-evident | `TestVerifyDetectsSingleByteTamper`, `TestVerifyDetectsReorderAndDeletion`, `TestWriterExtendsPersistentChainAcrossRestart`, `TestAuditTamperedExportDetected` |
| a removed head is detected — verification is anchored, not self-rooted | `TestHeadTruncationIsDetected` |
| archiving prunes only what it captured, re-anchors, and keeps the chain verifiable across archive + live | `TestAuditArchivePrunesAndKeepsTheChainVerifiable` |
| the public surface is stateless: no session is issued or read, no handshake is needed, GET and DELETE are 405 (§5.5) | `TestThePublicSurfaceIsStateless`, `TestStatelessMCPComposesOncePerRequestAndNeverForAGet` |
| an event crosses to every process on the store, a wait on one process wakes for a change another made and answers with the change log's cursor, never a clock; a cursor older than the log is said to be (§7.8, §8.5) | `TestAnEventCrossesToAnotherProcessOnTheStore`, `TestAProcessDoesNotHearItsOwnEventTwice`, `TestPostgresWakesAnotherProcessAtCommit`, `TestAWaitWakesForAChangeAnotherProcessMade`, `TestACursorOlderThanTheLogIsSaidToBe` |
| a caller's surface dropped, and an account adopted, re-sealed or forgotten, on one process is applied on another sharing the store (§11.1) | `TestAChangeOneProcessMakesToWhatItServesReachesAnother` |
| an account adopted or re-leafed after the owner changed the seal serves the new seal and stores it; a setting saved on one process is applied by every other and audited once (§8.2, §11.1) | `TestAnAccountAdoptedAfterASealChangeServesTheNewSeal`, `TestASettingSavedOnOneProcessIsAppliedByAnother` |
| a lease is one holder's at a time, renewed by it and anyone's once it runs out; blobs go where `blob_dir` says (§11.1) | `TestALeaseIsOneHoldersUntilItRunsOut`, `TestBlobsAreUnderTheDataDirUnlessBlobDirSaysOtherwise` |
| the retries and the retention pass run only on the process that holds their lease; a wait from a cursor past the log's newest change is answered at once with `cursor_expired` (§8.5, §11.1) | `TestARetryPassRunsOnlyWhileItLeads`, `TestTheRetentionPassRunsOnlyWhileItLeads`, `TestACursorPastTheLogIsSaidToBe` |
| an expired OAuth token is refreshed by one process of two on the store and served by both, with the rotated refresh token spent once (§6.3, §11.1) | `TestAnExpiredTokenIsRefreshedByOneProcessAndServedByAll` |
| a wake of the owner's wait reads the same rows at 1, 300 and 2000 contacts, and answers what counting every contact answered; the count reads by account and state together (§8.5) | `TestAWakeReadsTheSameRowsAt1And300And2000Contacts`, `TestCountingContactsByStatusReadsThoseRowsAlone` |
| one audit chain, however many writers: appends from several processes on one SQLite file and on one Postgres database make one verifying chain (§11.4) | `TestWritersInSeveralProcessesExtendOneChain` |
| the listener closes a connection past its cap before a handshake, audits the refusals once a minute, and admits the next once a slot frees (§5.7) | `TestTheListenerClosesAConnectionPastItsCapAndAdmitsTheNext` |
| behind the proxy `proxy_address` names, the caller's chain and address are what it forwarded, and from any other source neither header is read; a forwarded chain that does not read — two elements, two headers, no `Chain`, a lone certificate — proves nothing; `proxy_address` is an IP address (§5.1, §12.2) | `TestTheProxysForwardedChainAndAddressAreReadFromItAlone`, `TestAForwardedChainThatDoesNotReadProvesNothing`, `TestTheProxyAddressIsAnIPAddress` |
| `deploy/envoy` requests and forwards the caller's chain, replacing a caller's own header, puts the address its socket saw in the header the node reads, limits every route per source address with no bucket the sources share, holds the listener's connection cap and bounds, and its compose file trusts Envoy's address alone (§5.1, §5.7) | `TestEnvoyForwardsTheCallersChainAndAddressAsTheNodeReadsThem`, `TestEnvoyLimitsEveryRoutePerSourceAddressAndHoldsTheNodesConnectionCap`, `TestEnvoyHoldsARequestToTheListenersOwnBounds`, `TestTheEnvoyComposeTrustsEnvoyAloneAndRunsTheSidecar` |
| a sealed call completes from a 2026-07-28 client and from a handshake-era client, and the outbound client sends two sessionless POSTs (§5.5) | `TestASealedCallCompletesFromEitherMCPEra` |
| a withdrawn integration tool leaves the next request, repeatedly, and the cache stays within its bound | `TestWithholdingAnIntegrationWithdrawsItFromTheNextRequest`, `TestTheCacheStaysWithinItsBound` |
| outbound retries are scheduled by attempts made, so uneven sweeps cannot starve a message | `TestRetriesStayOnScheduleWhenSweepsAreUneven`, `TestRetryBackoffWidensWithAge` |
| a sender-chosen `expires` survives the store on both engines | `MessageExpiryHoldsAFarFutureDeadline` (both engines) |
| the fallback chain runs at once when no owner agent is attached (§6.8) | `TestAgentAnsweredKnowsAboutPresenceFromConstruction`, `TestOwnerPresenceIsARecentRequestOnAnyProcess`, `TestPresenceIsWrittenAtMostOncePerInterval`, `TestPresenceOutlastsTheLongestWait` |
| an answer given through one node process reaches a call held by another, and is reported relayed only on the holder's word, late otherwise (§6.8) | `TestAnAnswerGivenOnOneProcessReachesACallHeldByAnother` |
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
| an export carries one identity's contacts, chats and files and nothing else: exactly the format's members, none of a host's secrets or a stranger's request anywhere in its bytes, and a file the core reads whole (§3.10, HDTP §9.2) | `TestAnExportCarriesContactsChatsAndFilesAndNothingElse`, `TestAnExportRefusesWhatItCannotCarry`, `TestADanglingReplyTravelsAsNoReply`, `TestAMessageTheWriterLeftOutIsReported`, `TestAFileThatDoesNotReadBackIsRefused`, `TestAnExportSaysTrulyWhyItLeftAConversationOut`, `TestAMessageWaitingForItsHumanTravelsQueued`, `TestAnExportOverTheCloudsCeilingsSaysSo` |
| a former contact's conversation travels as a removed thread carrying its names, and its root is never a contact; a stranger's stays and is named by its id; the import writes the thread with its names, no contact, and gives a held contact its thread (HDTP §9.2, SEP-0004) | `TestAFormerContactsConversationTravelsAsARemovedThread`, `TestAStrangersConversationStaysWhenItsRowGoes`, `TestAFormerContactAskingAgainTravelsAndTheRequestStays`, `TestARemovedConversationArrivesAndNeverBecomesAContact`, `TestARemovedConversationJoinsAContactHeldHere`, store conformance `KeptWasContactCases` (testdata/kept_was_contact.json, which BatonDeck runs by name) |
| before an export is written, the person is told it is not encrypted, that anyone who gets it can read their contact list and all their conversations and files, and that it holds no keys (HDTP §9.2 #3, the full-export notice in the specification's words); the node writes no contact book | `internal/cli/portablecmd.go` (`exportNotice`) | `TestALostMasterKeyIsRecoveredByExportingAndImporting` (the output begins with the notice, which is printed before the file is opened) |
| an import brings the contacts, the chats and the files, and nothing of the old host's — no key, no ledger, no invite, no retry queue, no trust flag or card — on SQLite and Postgres alike; a new slug holds the file's root and nothing more (§3.10) | `TestARoundTripKeepsWhatAnExportCarries`, `TestANewSlugHoldsOnlyTheFilesRoot` |
| an import refuses every hostile file of hdtp-identity's shared corpus with the words the corpus names — the core's exactly, the host's in CONTRACT §6.2's — and writes nothing; it accepts both valid files whole (§3.10, HDTP §9.2) | `TestTheCorpusIsImportedAsTheCoreReadsIt` |
| an import is one transaction on both engines; into the identity it belongs to it merges, never replacing a held pin and merging nothing into a stranger's request held here (skipped, and the review says so), and counts what it wrote, what it filled and what was already here (a file by its record, a pin fill apart from a contact added); the review, printed before anything is written on every run, refuses what the write would; it ends with the request for the next leaf, minted; a contact arrives with every column an export carries and none it does not (§3.10, §11.1) | `TestAnImportIntoTheSameIdentityMergesAndNeverReplacesAHeldPin`, `TestAHeldRequestIsSkippedWhenTheFileNamesTheSameRoot`; store conformance: `AtomicallyLandsEverythingOrNothing`, `ImportContactWritesWhatAnExportCarries`, `TestAnImportCountsWhatItWrote`, `TestAFileThreadIsNotMergedIntoAnotherContactsThread`, `TestAFileMessageWhoseIDIsTakenIsRefused`, `TestAnOwnerNameWithAControlCharacterIsRefusedAtTheReview`, `TestAnImportsMemoryFollowsItsMessages`, `TestAnImportShowsItsReviewAndEndsWithARequestItMinted`, `TestAMergeKeepsAHeldBlockAndSaysSo` |
| there is no `backup`, and neither export verb touches anything when typed bare (§12) | `TestTheExportVerbsCostNothingWhenTypedBare` |
| a lost master key costs a node its leaves and not the identity: a renewal under the same root installs, and the key it can no longer open is retired and reported (§3.10, HDTP §14.4) | `TestALostMasterKeyCostsALeafNotTheIdentity`, `TestALostMasterKeyIsRecoveredByExportingAndImporting`, `TestAnAccountWhoseKeyWillNotOpenIsNamedNotHidden`, `TestServeNamesAnAccountWhoseKeyWillNotOpen`, `TestOneBrokenAccountStopsTheNodeOnlyWhenNothingProvesTheMasterKey` |
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
| withholding an integration withdraws its tools from the next request (§6.5, §6.10) | `TestWithholdingAnIntegrationWithdrawsItFromTheNextRequest` |
| a repin keeps the pinned key when the call proved none | `TestSQLiteConformance` |
| the LAN flag is judged per request, so a live flip takes effect | `TestLANGuardDecidesPerRequestNotAtWiringTime` |
| ingress pairing works from the portal, and an unpaired ingress adapter cannot be selected | `TestIngressPairingFromThePortal`, `TestSelectingAnIngressAdapterWithoutPairingIsRefused` |
| the media quota is the documented one and is configurable per account | `TestDefaultQuotaMatchesTheSpec`, `TestStorageSettingsPersistAndApply`, `TestQuotaExceededError` |
| retention deletes past the window, keeps referenced blobs, and never deletes on a guess | `TestRetentionDeletesPastTheWindowAndKeepsLiveBlobs`, `TestUnlimitedRetentionDeletesNothing`, `TestSharedBlobBytesSurviveUntilTheLastReferenceGoes`, `TestUnreadableMediaBodyStopsBlobDeletion` |
| an interrupted archive is repairable, not reported as tampering (§11.6) | `TestInterruptedArchiveIsRepairableNotTampered`, `TestRepairRefusesWithoutItsArchiveFile` |
| the last passkey can never be removed, from any surface | `RemoveCredentialIfNotLastKeepsTheLastOne`, `TestSQLiteConformance`, `TestPostgresConformance` |
| the owner can read stored media, scoped to their account (§7.4, §8.2) | `TestOwnerCanReadStoredMediaButNotAnotherAccounts` |
| the inbox's unread counts are read at runtime from each conversation's read marker over one page, capped, and summed for the sidebar under the same cap; showing a conversation, or `read_thread`, marks it read through the newest message shown, refusing a conversation that is not this identity's (§8.2, §8.5) | `TestEachConversationCountsItsUnreadAndThePageSumsThem`, `TestAConversationOverTheCapSaysCapped`, `TestThePagesTotalStopsAtTheCap`, `TestUnreadPastThePageMakesTheTotalAFloor`, `TestShowingAConversationZeroesItsCount`, `TestMarkingReadRefusesWhatIsNotThisIdentitysConversation`, `TestAnEmptyInboxCountsZero`, `TestReadThreadMarksTheThreadReadThroughWhatItReturned`, `TestTheSpecSaysTheInboxPageAndCap`, `TestSQLiteConformance`, `TestPostgresConformance` |
| a contact's URL is fetched only when the owner asks (§7.5) | `TestMediaFetchIsOwnerInitiatedAndReportsRefusal`, `TestPrivateRangeFetchRefusedAndAudited` |
| `get_status` answers node-local status with no integration (§6.7) | `TestGetStatusAnswersWithoutAnyIntegration` |
| an agent-answered exposure parks a request naming its caller (§6.8) | `TestAgentAnsweredExposureParksARequest` |
| the portal consumes the SSE stream it serves (§8.1) | `TestPortalPagesConsumeTheEventStream` |
| the owner MCP is stateless for both MCP eras, and a revoked token is refused on its next request (§3.4, §8.4, §8.5) | `TestTheOwnerMCPIsStateless` |
| the owner MCP requires a token on every bind (§8.3, §8.4) | `TestOwnerMCPRequiresATokenEvenOnLoopback` |
| integration management on the owner MCP shows exposure, not the catalog (§8.4) | `TestIntegrationToolsShowExposureNotTheUpstreamCatalog` |
| every owner-MCP call is audited, reads and refusals included (§8.7) | `TestEveryOwnerMCPCallIsAudited` |
| the owner surface declares no subscriptions; a message is found with `wait_for_updates` and read through `hdtp://inbox` and `hdtp://thread/<id>` (§8.5) | `TestTheOwnerSurfaceOffersNoSubscriptionsAndAMessageIsReadable` |
| the front door drops rather than blocking when the terminator is gone | `TestFrontDoorDropsWhenTheTerminatorIsNotAccepting` |
| the messages table keeps a thread's order, admits the four statuses and no other, and takes a message id once per contact and direction | `TestMessagesKeepTheirOrderStatusesAndUniqueness` |
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
| config precedence is environment > file > store > defaults (§12.2), for `doctor` as for `serve` | `TestConfigFileOutranksOwnerSetSettings`, `TestSettingsPersistAcrossRestartAndReDerive`, `TestDoctorReadsThePublicURLThePortalSaved` |
| the audit chain distinguishes owner actions from caller actions | `TestOwnerActionsAreAuditedAsOwner`, `TestAuditPageFiltersByActor` |
| `audit_query` never leaves the identity's accounts | `TestAuditQueryNeverLeavesTheIdentitysAccounts`, `TestScopedTokenCannotReadNodeLevelAuditRows` |
| owner-MCP tools cannot reach another account's integration, and answer it as one that does not exist | `TestSetExposureCannotReachAnotherAccountsIntegration`, `TestSetExposureAnswersAForeignIntegrationAsAMissingOne` |
| the portal's integration routes cannot reach another account's integration, and answer it as one that does not exist | `TestIntegrationRoutesRefuseAnotherAccountsIntegration` |

## HDTP 1.0: the person is the certificate authority

HDTP 1.0.0 (§2, §3, §5.3, §9, §9.1, §9.2, §13.2, §14) on this node. The library the rules live in is
`github.com/humandelegatedtrustprotocol/hdtp-identity/go` (the version `go.mod` requires), proven against
Appendix B by its own tests; these are the node's.

| Clause | Where it lives | Tests |
|---|---|---|
| a leaf the wallet issued is installed only when it validates to the account's root, carries the requested key and is newer than the current one (§14.2, §14.3) | `internal/identity/leaf.go` | `TestLeafSignupThenRenewThenMove`, `TestInstallLeafRefusals` |
| a `v: 1` envelope is decided by the library and the effects applied: guest binding, both forms, tiers (§13.3, §6.1) | `internal/public/decide.go` | `TestFirstContactMustRedeemOrRequest`, `TestPinnedContactBothForms` |
| a client-certificate chain resolves through the same pin rules as an envelope — superseded or blocked to guest, a new address by `accept_new_hosts` (§2, §5.3, §14.3). These are the node's OWN resolution, written against the library's rules rather than delegated to `Decide`, which is why they are their own row | `internal/public/decide.go` (`ResolveTransport`) | `TestTransportPinChecks`, `TestATransportChainResolvesThroughThePinChecks` |
| `chain_required` is one answer for unknown, blocked, expired and a bad signature, and spends the guest budget (§13.2, §14.5) | `internal/public/decide.go`, `sealed.go` | `TestSmallFormUnknownBlockedAndBadSignatureAreOneAnswer` |
| a pin has three states (CONTRACT `Pin`: active, pending_out, blocked) and the node hands Decide only rows in one of them, as BatonDeck does: a request the owner has not answered (`pending_in`) is no pin, so its small form is `chain_required`, its chain form a stranger's, its audit row a guest's, and Decide's effects for an active pin reach no unanswered request (SPEC §5.4, the owner's decision of 2026-09-30); a row in any other state — one the schema does not admit — is handed over as no pin too, its holder decided the same way, and the row is counted and named by `serve`'s banner and `check store` (the row below) | `internal/public/decide.go` (`pinsOf`, `UnknownContactState`) | `TestAPendingRequestIsHandedToDecideWithNoPin`, `TestARowInAStateThisNodeDoesNotKnowIsHandedToDecideAsNoPin` |
| every card and certificate the store holds is read by the identity core's rule — a card as every write to that contact reads it, a certificate as the core parses it — and each that does not read is named by table, row and field with the reason, and each contact in a state neither a pin nor a request has (`public.UnknownContactState`, the one reading `pinsOf` leaves such a row out by) is counted in the `store:` line and named by row and status (`NO PIN`): in `serve`'s banner, which serves whatever it says, and by `check store`, which exits 1 on one of either; nothing is changed (SPEC §12.1) | `internal/storecheck/storecheck.go`, `internal/cli/checkcmd.go`, `internal/cli/serve.go` (`announce`) | `TestTheRunNamesEveryCardAndCertificateThatDoesNotRead`, `TestAStoreWhoseFieldsAllReadSaysSo`, `TestAContactInAStateNoPinHasIsCountedAndNamed`, `TestCheckStoreNamesTheCardThatDoesNotReadAndExitsOne`, `TestCheckStoreNamesTheContactInAStateNoPinHasAndExitsOne`, `TestCheckStoreRefusals`, `TestServeNamesTheCardThatDoesNotReadInItsBannerAndServes` |
| a stale kid is answered `certificate_renewed` with the current chain, in plaintext (§14.4) | `internal/public/sealed.go` | `TestStaleKidIsAnsweredWithTheCurrentChain` |
| a sealed answer carries the chain until the contact has seen the current leaf and the fingerprint after, except the answer to `get_card`, which carries the chain whatever the node has recorded; a chain-form answer, `get_card`'s included, is recorded as the chain sent (§13.2) | `internal/public/sealed.go` (`sealResult`) | `TestGetCardIsAnsweredWithTheChainOnceTheContactHasSeenIt`, `TestAFreshContactsGetCardIsRecordedAsTheChainSent`; live battery: "get_card is answered with the chain once this contact has seen the node's leaf" |
| an answer that verifies under no leaf held for the peer is followed by one `get_card` (plaintext to a peer that takes plaintext, sealed to the pinned leaf of a `required` one), a re-pin from its chain and one retry under the same `msg_id`; a `get_card` that does not verify, or is refused, ends the call naming both failures, and no second one is asked (§13.2, §14.3, §14.4) | `internal/outbound/seal.go` (`sealedExchange`, `repinFromSealedGetCard`) | `TestAnUnverifiableAnswerFromARequiredPeerIsFollowedByOneSealedGetCard`, `TestAnUnverifiableAnswerFromARequiredPeerWhoseGetCardAnswersByTheRecordFailsNamingBoth`, `TestAnUnverifiableAnswerFromAnOptionalPeerIsFollowedByOnePlaintextGetCard`, `TestASealedGetCardAnsweredCertificateRenewedFailsTheCallAndTheNextCallFollowsIt`, `TestASealedGetCardAnsweredUnderAChainThatIsNotThePeersCurrentLeafMovesNoPin`, `TestAnAnswerCarryingTheRenewedChainRepinsWithoutGetCard` |
| the newest leaf wins; a new address re-pins under `auto`, waits under `ask`, and a removed root returning is asked about (§14.3, §5.3) | `internal/public/decide.go`, `internal/contacts/manager.go` | `TestNewestLeafWinsAndNewAddresses`, `TestTombstoneForcesTheQuestion` |
| a caller at an address the owner has not approved is told once however often it calls, and every such answer spends the guest budget (§5.3, §14.5) | `internal/public/decide.go`, `sealed.go` | `TestAnUnapprovedAddressIsToldOnce` |
| the chain is the client certificate; a contact's chain as its server certificate validates to the pinned root at the dialed address (§2, §14.2) | `internal/outbound/client.go` | `TestClientPresentsItsChain`, `TestChainAsServerCertificateValidatesToThePinnedRoot` |
| a pin is confirmed when it is needed and the node polls nobody: ONE contact's card is re-fetched, when its owner asks from that contact's page or the owner MCP's `refresh_contact`; an unanswered or refused refresh changes no pin, and a refresh can learn a renewed leaf and never a root or an address (§14.3) | `internal/node/refresh.go` | `TestNothingRefreshesContactsByItself`, `TestARefreshReachesOnlyTheContactThatWasNamed`, `TestAnUnansweredConfirmationChangesNoPin`, `TestVerifyRefreshedCard`, `TestARefreshLearnsARenewalAndNeverAnAddress`, `TestRefreshingOneContactOverTheWire` |
| what moves between hosts is data and never a key: the exporter holds none to write and the importer refuses one (§9) | `internal/portable/export.go`, `internal/portable/import.go` | `TestAnExportCarriesContactsChatsAndFilesAndNothingElse`, `TestTheCorpusIsImportedAsTheCoreReadsIt` (`key-in-a-cell.zip`, `key-in-a-body.zip`) |
| a host accepts a web wallet's answer only once, only with the state it minted for a pending request, and only a chain whose leaf carries that request's key and validates at its endpoint; the signing request carries exactly the members a wallet takes (HDTP §9.1) | `internal/identity/walletreq.go`, `internal/identity/leaf.go` (`InstallWalletLeaf`), `internal/cli/leafservice.go`, `internal/internalui/wallet_pages.go` | `TestAWebWalletsAnswerIsAcceptedOnceAndOnlyWithItsState`, `TestTheStateIsConsumedByTheStatementThatChecksIt`, `TestWalletPurposeIsTheRuleTheInstallMovesBy`, `TestTheWebWalletSigningRequestOnARunningNode`, `TestTheWalletReturnPageNeedsNoSessionAndHoldsNoData`, `TestTwoAnswersTogetherInstallOnce`, `TestConcurrentRequestsLeaveOnePending`, `TestAnInstallWhoseNodeCannotReloadIsInstalledWithAWarning`, `TestARefusedRequestIsAudited`, `TestTheWalletStartPageCarriesNoErrorText`; store conformance: `OnePendingRequestAndReplacingItIsOneStep`, `TestThePortalsLoopbackRuleIsTheWallets`, `TestASignedOutWalletPageSendsThePersonToSignIn`, `TestTheWalletURLIsAStrictOrigin`, `TestAWalletURLThatIsNotAnOriginRefusesTheConfig`, `TestARequestForAnAddressNoWalletCertifiesIsRefused`, `TestDoctorNamesAPublicURLNoWalletCertifies`; wallet_return_test.mjs: a refusal code shown as a fixed sentence |
| when the person leaves — after a review, with `-yes`, and not while this node serves the identity at its own address unless `-force-current` — the leaf keys and every record of the identity go at once and the address answers as one never served; the address is free at once, every identity here being the operator's (§9) | `internal/identity/leave.go`, `internal/cli/serve_admin.go` | `TestSQLiteLeaveErasesEveryRowThatNamesTheIdentity`, `TestPostgresLeaveErasesEveryRowThatNamesTheIdentity`, `TestAccountLeaveOnARunningNode`, `TestNoCampaignStartsWhileTheWorkHoldsTheSlot` |
| after a leave, the audit rows that name the identity by its account id (its column, or `account:<id>` in the resource) stay in the live trail for `audit_archive_after` (90 days by default), and the hourly sweep then moves every one of them still in the table (a row an `audit archive -through N` had already moved stays in the head archive) to `<data_dir>/audit-archive/<account-id>-<first>-<last>.jsonl` (0600) with one `audit_archive` row naming the segment and its hashes and not the identity; nothing moves a second early, nothing of an identity still here moves, the prune guard admits the delete only for rows listed with their hashes in the one transaction that removes them, a run stopped at any step loses and duplicates no row and writes one `audit_archive` row, `audit verify` walks the table and every archive as one chain and reports a changed, cut or missing archive as broken, and `audit erase-archive` reduces an archive to seqs and hashes when law requires. After the period the live trail holds nothing that names the identity by its id; the archive is kept (the owner's decision), and erasing it is how HDTP §9's "keep nothing beyond what law compels" is met where law asks for less (§9) | `internal/core/audit/departed.go`, `internal/core/audit/archive.go`, `internal/core/store/audit_anchor_{sqlite,postgres}.go` (`ArchiveAuditRows`), `migrations/*/0001_base.sql`, `internal/cli/auditcmd.go`, `internal/services/retention/retention.go` | `TestTheTrailOfAnIdentityThatLeftMovesOnlyAfterItsPeriod`, `TestOneAuditArchiveRowPerSegment`, `TestATamperedArchiveIsDetected`, `TestACrashMidArchiveLosesAndDuplicatesNothing`, `TestTheTriggerStillRefusesAnyOtherDeletion`, `TestAWriterAfterAnArchiveExtendsTheChain`, `TestHeadAndIdentityArchivesVerifyTogether`, `TestAnErasedArchiveStillLinksTheChain`, `TestAccountLeaveOnARunningNode`, `TestEraseArchiveRefusals`, `TestTheAuditTrailOfALeaveIsArchivedAfterItsPeriod`, `TestAuditArchiveAfter` |
| a leaf key destroyed at a leave, an expiry or an install is gone from the database file and its write-ahead log on SQLite (`secure_delete`, then a checkpoint that truncates the log, proven by the log's size). On Postgres it is not: a deleted row stays as a dead tuple, in the write-ahead log and in backups, sealed under the node's keyring (AES-256-GCM) — a named divergence from HDTP §9's "destroy" (SPEC §3.9) (§9) | `internal/core/store/sqlite.go` (`Scrub`), `internal/identity/leave.go`, `internal/identity/leaf.go` | `TestALeaveLeavesNoLeafKeyOnDisk`, `TestARetiredLeafKeyIsNotLeftOnDisk` |
| after an import, the first leaf requested after it — a move or not — handshakes every imported contact that is not blocked, and a leaf that is not a move calls nobody else: a peer that pins the root takes `update_contact`; one that refuses it is marked `pending_out` and then sent `request_contact` (only an owed contact is), decides under its own policy, and a refusal is recorded `refused` and never asked again; a request that did not arrive is taken back; each outcome is audited, a contact told is owed nothing more, a contact whose leaf is not held is recorded `unreached` once, never called and counted apart; the fallback's request expires a full window after it was made; `announce` resumes nothing for a slug with no leaf (HDTP §9.2) | `internal/identity/fanout.go`, `internal/node/announce.go`, `internal/node/request.go` | `TestAfterAnImportTheNextLeafHandshakesEveryImportedContact`, `TestTheCampaignWalksAnImportsContactsOnceAndNeverABlockedOne`, `TestARenewalAfterAnImportCallsOnlyTheImportedContacts`, `TestAMoveDoesNotAskARefusingContactThatWasNotImported`, `TestARefusedHandshakeIsNotAskedAgain`, `TestTheFallbackRecordsTheApproachBeforeSendingIt`, `TestAFallbackThatDidNotArriveIsTakenBack`, `TestAFallbackRequestIsNotSweptForTheContactsAge`, `TestTheHandshakeIsNotSpentOnTheLeafTheImportFound`, `TestOwedHandshakesAreNamedByAccountCertificateAndDoctor`; store conformance: `ImportContactWritesWhatAnExportCarries`, `TheExpiryWindowRunsFromTheRequest` |
| the exit demonstration: two nodes pair as identities, message in both forms, one renews and the other learns the leaf from the answer and follows `certificate_renewed`, one moves and the other follows under `auto` | `internal/node/exit_demo_test.go` | `TestExitDemo` |

The hosted platform's live conformance battery (BatonDeck's, whose source is not public) gains a `certificate` group
built on the library alone — the card decodes, a stranger's small form is
`chain_required`, a stranger's full form may only redeem or request, a card to
another root is refused, a contact pairs and speaks in the small form, a
superseded leaf is a guest, a move re-pins or waits, and a stale kid (when one
is named) is `certificate_renewed`. Against a node whose card is not a card it FAILS; it
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
directly or transitively, by `cmd/hdtp-gateway`; and no exported `New*`
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
golang.org/x/tools/cmd/deadcode, rooted at `cmd/hdtp-gateway`, which follows
calls rather than names and sees unexported functions too. Its report is held to
this same table by `TestDeadcodeFindsOnlyWhatTheTableExcuses` — a function it
finds must be excused here by its `Type.Method` or `pkg.Func`, or sit in an
excused package. The table's staleness stays with the hermetic gate, which is
why a row the deadcode report alone needs must also be one the fourth check
needs.

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
| `internal/limits/limitstest` | Test-support by construction: it runs the real limits sidecar (`cmd/hdtp-limitd`) for a test and reads the shipped rules from `deploy/limitd/limits.json`, so every test that stands a node up meets the budgets a node meets. Nothing in production imports it. | — |
| `internal/testid` | Test-support by construction: it builds the roots, leaves and cards an identity needs, so that nine test files across six packages do not each grow their own wallet. Nothing in production imports it. | — |

Method-level gaps. Four of these are Go interface dispatch — the runtime calls
them, no source names them — and the rest are debt with a task against it.

| Not reached | Why | Tracked by |
|---|---|---|
| `ownerUser.WebAuthnID` | Interface dispatch: `go-webauthn` calls it through `webauthn.User`. | — |
| `ownerUser.WebAuthnName` | Interface dispatch, as above. | — |
| `ownerUser.WebAuthnDisplayName` | Interface dispatch, as above. | — |
| `ownerUser.WebAuthnCredentials` | Interface dispatch, as above. | — |
| `Server.WithFactsForTest` | Test seam onto the facts middleware, so a test can assert what a request is SEEN as rather than asserting on the flag that decides it — which is the difference between pinning behaviour and pinning a variable. | — |
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

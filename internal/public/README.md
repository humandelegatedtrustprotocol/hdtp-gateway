# internal/public

The node's HDTP-facing surface (SPEC.md §5): what contacts and guests call. It is the one place a caller's identity is decided and the one place the built-in guest, pending and contact tools are defined. `internal/node` composes it (`node.New` builds the `Server`, the `LANGuard`, the `ConnCap` and the body cap; `node.go` builds one `Pool`, `Identifier` and `Registry` per account, adds `BuiltinEntries` and `SealedEntries`, and swaps integration groups in with `Registry.Replace`), and `internal/cli/compose.go` uses `StatelessMCP` and `CapBody` for the owner MCP. The package calls `internal/core/policy` (Cedar, `policy.Allow`), `internal/contacts`, `internal/messaging`, `internal/calendar` (through small interfaces), `internal/core/store`, `internal/envelope`, `internal/tunnel` (the probe path), and hdtp-identity for the chain and envelope work. It decides no budget: `Pool.Limit` and `Pool.PreOpen` are hooks the node fills from the limits sidecar.

## What it holds

Listener and transport (listener.go, conncap.go, lan.go, bounds.go, stateless.go):
- `Server`: the route shell. `/a/{slug}/mcp`, `/mcp` (only while exactly one account), `/i/{token}`, the reachability probe; facts middleware; `TLSConfig` requests a client certificate and never requires or chain-verifies one.
- `TransportFacts`, `WithFacts`, `FactsFrom`: what the connection proved. Only a client chain that validates (HDTP §14.2) fills the identity fields; `ChainProven` is true then. Behind the configured proxy (`ProxyAddress`), the chain comes from `ProxyCertHeader` and the address from `ProxyAddressHeader`; from any other source both are ignored.
- `ConnCap`, `DefaultMaxConns`, `LANGuard`, `CapBody`, `AuditFn`, `Limits`, `LimitsWith`: connection cap, LAN flag, body cap, and the limits get_card advertises.
- `StatelessMCP`, `ToolsOnly`: stateless Streamable HTTP and the capability set (tools, no `listChanged`).

Tools and servers (tools.go, servers.go, resolver.go):
- `BuiltinEntries`, `ToolDeps`, `Calendar`, `StatusSource`, `CardFn`, `Slot`, `MaxTextBytes`, `MaxNoteBytes`, `MaxInlineData`, `MaxFieldBytes`: the built-in guest, pending and contact tools, defined only here.
- `Registry` (`Add`, `Replace`, `GatedPermissions`), `Entry`: every tool as data, in groups; an integration is a group that can be replaced or removed.
- `Pool` (`NewPool`, `ServerFor`, `Invalidate`, `InvalidateAll`, `Dispatch`), `CallerResolver`, `StoreResolver`, `WithCaller`, `CallerFromContext`, `Charge`, `Refusal`: per-caller servers in a bounded LRU cache, composed from what `policy.Allow` grants and re-checked at call time.

Identity and sealed calls (identify.go, decide.go, sealed.go):
- `Identifier` (`OpenSealed`, `PlaintextGateCtx`, `PoolGate`, `ResolveTransport`, `Replay`), `EnvelopeFacts`, `Payload`, `RecipientState`, `TransportCaller`, `EnvelopeKey`, `Code`: the seal and client-cert policy, the open (via hdtp-identity's `Decide`, with the effects applied here), the transport-side pin checks, the replay record and the error-to-wire-code map.
- `SealedEntries`, `SealedDeps`, `SealedToolName`, `ResultLifetime`: the `sealed_call` wrapper, registered once per tier.
- Errors: `ErrSealRequired`, `ErrIdentityRequired`, `ErrSealNotAccepted`, `ErrPendingApproval`, `ErrPendingStatus`, `ErrChainRequired`, `ErrUnavailable`, `*CertificateRenewed`, and `TierPendingAddress`.

## What it refuses, and how

The tools (each answers an HDTP §12 code on failure and writes an audit row; tiers are exact, a caller sees only the entries of its own tier):

| Tool | Tier, permission | Refusals | Spec |
|---|---|---|---|
| `redeem_invite` | guest | `bad_request` (arguments do not decode); `too_large` (card over `MaxTextBytes`, token over `MaxFieldBytes`); the contacts manager's `invite_invalid`, `identity_required`, `unknown_contact`, `bad_request` (the manager returns no `too_large`; the tool emits it for the caps above); `unavailable` (any other failure, or no card or chain to answer with). When the contacts manager answers silently (a held root served as a stranger, SPEC.md §9.1) the caller's cached server is not invalidated and the audit outcome is `blocked_silent` for a blocked row, `ok` otherwise. | HDTP §6.2, §4; SPEC.md §9.1 |
| `request_contact` | guest | `bad_request`; `too_large` (note over `MaxNoteBytes`, card over `MaxTextBytes`); `unavailable` (requests list full); `pending_approval` (the caller already has a request waiting); any other held row (blocked, active, pending_out) is answered `{"status":"pending"}` and nothing is written; manager codes as above. | HDTP §6.2; SPEC.md §5.4, §9.1 |
| `contact_accepted` | pending | `bad_request`; `too_large` (card over `MaxTextBytes`, more than 64 permissions, one over `MaxFieldBytes`; emitted by the tool); manager codes (`unknown_contact`, `bad_request`, `identity_required`, `invite_invalid`, else `unavailable`). | HDTP §6.1, §6.2 |
| `contact_rejected` | pending | `bad_request`; `too_large` (reason over `MaxNoteBytes`; emitted by the tool); manager codes. | HDTP §6.2 |
| `get_card` | contact, none | `unavailable` (no card, no chain, no limits function, or the limits could not be read). Carries the signed card, `card_sig`, the chain and `limits`. Its sealed answer carries the node's chain whatever the contact has seen (`sealResult`), and records it as sent like any chain-form answer. | HDTP §6.2, §12, §13.2 |
| `update_contact` | contact, none | `bad_request`; `too_large` (card over `MaxTextBytes`; emitted by the tool); manager codes. | HDTP §5.3, §14.3 |
| `remove_contact` | contact, none | manager codes. | HDTP §6.2 |
| `send_message` | contact, `message.text` | `unavailable` (no messaging service); `bad_request` (arguments; `sender` other than `""`, `agent` or `human`); `too_large` (text over `MaxTextBytes`; `topic`, `msg_id`, `thread_id`, `reply_to` over `MaxFieldBytes`); messaging errors mapped to `bad_request`, `too_large`, else `unavailable`. | HDTP §6.2, §7; SPEC.md §7 |
| `send_media` | contact, `message.media` | `unavailable` (no media or messaging service); `bad_request` (arguments, bad base64, neither `data` nor `url`, bad `sender`); `too_large` (short fields over `MaxFieldBytes`; `data` over the encoded length of `MaxInlineData`, checked before decoding, then decoded over `MaxInlineData`). A `url` is recorded and never fetched. | SPEC.md §7.5, §5.7 |
| `get_status` | contact, `status.view` | `unavailable` (no status source, or it failed). The answer is one of `available`, `busy`, `dnd`, `offline`; any other value is sent as `busy`. | HDTP §6.2 |
| `check_availability` | contact, `calendar.availability` | `unavailable` (no calendar or it failed); `bad_request` (window times not RFC 3339, `to` not after `from`, `duration_min` not positive). At most `calendar.MaxSlots` slots, in the requested IANA zone (UTC when empty or unknown). | HDTP §6.2, §12 |
| `book_slot` | contact, `calendar.book` | `unavailable`; `bad_request` (empty `msg_id`, bad slot times, `end` not after `start`); `too_large`; calendar errors mapped as above. | HDTP §6.2 |
| `cancel_booking` | contact, `calendar.book` | `unavailable`; `bad_request` (empty `booking_id`); `too_large` (`booking_id` over `MaxFieldBytes`, reason over `MaxNoteBytes`). | HDTP §6.2 |
| `sealed_call` | every tier, ungated | see below | SPEC.md §4, §5.3 |

Beyond the tools:
- A tool outside the caller's tier or permission is answered by tier: `blocked_or_unknown` at guest (a blocked caller and a stranger get the same answer, SPEC.md §5.4), `pending_approval` at the pending tier, `permission_denied` at the contact tier (`refusalCode`). SPEC.md lines for §5.4 and §5.8 still word the pending-tier case as `permission_denied`; they predate SEP-0003 (Final 2026-10-07), which amended HDTP 1.0 to `pending_approval` at the pending tier (hdtp-spec `docs/specification/1.0/mcp-server.md` and `errors-limits-conformance.md`). The code and `TestThePendingTierIsRefusedPendingApproval` follow HDTP 1.0 as amended; SPEC.md is the stale side and is to be corrected separately.
- A dependency failure while composing or checking is `unavailable` and audited as one, not as a denial (`ErrUnavailable`).
- A pinned root calling over TLS from an address the owner has not approved is composed as a guest and every substantive call is answered `pending_approval`; `update_contact` answers `{"status":"pending"}`.
- Transport gate (`Identifier.PlaintextGateCtx`, in `Pool.Gate`): under `client_cert: required` a call without a validated chain is `identity_required`; under `seal: required` a plaintext substantive call is `seal_required`, or `identity_required` first when no identity was established.
- `sealed_call`: before the open, a source that has not carried a proven active or pending contact's call to the account in the last hour (the limits sidecar remembers it for an hour: `internal/limits/client.go`, SPEC.md §5.7) is refused `rate_limited` in the clear when the guest total is spent; `envelope_invalid` for anything that does not parse or open (plaintext); `seal_not_accepted` when the account's seal policy is `none`; `chain_required` (plaintext, and charged to the source's budget); `certificate_renewed` (plaintext, with the current chain); a refusal of an opened envelope that proves nobody also spends one unit of the guest total. Once `OpenSealed` has returned facts, every refusal is sealed back: `pending_approval` (a pending_out contact calling anything but its tier's tools, or a root at an unapproved address), `rate_limited` and `unavailable`, and the inner call's own result. A sealed result that cannot be sealed is answered `unavailable`; a refusal that cannot be sealed goes out as itself. A sealed answer carries the node's chain until the contact has seen its current leaf (`contacts.chain_sent_kid`, written when a chain-form answer goes out) and the leaf's fingerprint after — except the answer to an inner `get_card`, which carries the chain always (HDTP §13.2: it is what a caller that cannot verify an answer asks). A replayed envelope returns its recorded answer and spends nothing. The envelope's replay record is kept until `min(exp, ts + skew + 1)`.
- `envelope_invalid`, in plaintext, when the client certificate's key is not the envelope leaf's key (the envelope has opened by then, but `OpenSealed` has not returned facts).
- Network rules: the body is capped by the bytes read, not the declared length, with HTTP 413 and `{"code":"too_large"}`; `ConnCap` closes a connection past its `Max` as it is accepted, below TLS, and audits at most one `listener_full` row a minute with the count; `LANGuard` answers 403 `{"code":"unavailable"}` for a private-range source, but only when a non-direct tunnel adapter is active and the flag is off (it is inert with no adapter or `direct`, and a request carrying the adapter's trusted header passes; SPEC.md §5.1) (RFC 1918, unique-local, link-local, unspecified, and `100.64.0.0/10`; loopback is not refused) and audits `lan_refused`; any method but POST on an MCP endpoint is 405 with `Allow: POST`. The limits themselves are set by the node: `MaxBodyBytes` (8 MiB) and `DefaultMaxConns` (1024) are the values the node uses; the caps on text, notes and media are the constants above.

## Invariants

- No handler reads an identity out of its arguments: the caller is `CallerFromContext`, `EnvelopeFactsFrom`, or the transport facts.
- A single certificate is never an identity; only a validated chain fills `TransportFacts` and `EnvelopeFacts`.
- `policy.Allow` is re-checked inside the handler path on every call (`Pool.checked`), so a revocation is instant; the cache is only a performance layer.
- The built-in tool set equals `core.ReservedToolNames` together with `sealed_call`.
- A sealed request that opened gets a sealed answer; plaintext is for envelopes that did not open, and for answers that cannot be sealed.
- Every malformed built-in call is audited as a refusal; audit outcomes are verdicts only (the free text goes into the resource, redacted and cut to 160 bytes).
- A budget refusal of a sealed inner call is not recorded as the envelope's answer, so the same envelope sent again once the budget holds is served.
- The wrapper `sealed_call` is exempt from the per-call budget at the guard; the inner call is charged once, after the replay check.

## Held by

- `tools_test.go`: `TestBuiltinToolSurfacePerTier`, `TestBoundaryCapsRejectOversizedInput`, `TestSendMessageRecordsAndIsIdempotent`, `TestCalendarToolsRespectSlotCapAndBookIdempotently`, `TestUnconfiguredCapabilityIsUnavailable`, `TestGetStatusClampsToTheSpecVocabulary`, `TestGetCardAdvertisesTheLimitsInForce`, `TestBlockedCallerIsIndistinguishableFromAStranger`, `TestRedeemByABlockedRootReadsAsAStrangersRedemption`, `TestRefusalReasonsAreRedactedBeforeTheyAreAudited`, `TestALongReasonIsRedactedBeforeItIsTruncated`, `TestAuditOutcomesAreSingleVerdicts`.
- `refusal_audit_test.go`: `TestEveryMalformedCallIsRefusedAndAudited`. `reserved_test.go`: `TestTheReservedToolNamesAreTheBuiltInSet`.
- `servers_test.go`: `TestToolsListPerTier`, `TestPermissionFlipIsServedToTheNextRequest`, `TestCallTimeDenyOnAServerComposedBeforeTheRevocation`, `TestThePendingTierIsRefusedPendingApproval`, `TestEveryRefusalIsAuditedAndAvailabilityIsNotADenial`, `TestRegistryGroupsAreRevisableAndAccountWideRebuildReachesOpenCallers`, `TestTheCacheStaysWithinItsBound`.
- `sealed_test.go`, `sealederr_test.go`, `sealed_audit_test.go`, `pendingout_test.go`, `sealedreads_test.go`, `budget_test.go`, `guesttotal_test.go`: the wrapper at every tier, replay, `seal: none`, sealed refusals, who-acted audit rows, the budget-once rule and the guest total before the open. `getcardform_test.go`: `TestGetCardIsAnsweredWithTheChainOnceTheContactHasSeenIt` (the chain first, the leaf once the record says the chain went, the chain for `get_card` whatever the record says, and the record unchanged by it), `TestAFreshContactsGetCardIsRecordedAsTheChainSent` (a fresh contact's first sealed call is `get_card`: answered with the chain, recorded as sent, and the next answer names the leaf).
- `decide_test.go`, `decide_candidates_test.go`, `replaywindow_test.go`: the open decisions (both forms, one answer for unknown/blocked/bad signature, stale kid, newest leaf, new addresses, tombstones, transport pin checks, one spelling per member, a pending request handed to Decide with no pin, the pins handed equal to every contact's), and the replay window.
- `listener_test.go`, `clientcert_test.go`, `proxy_test.go`, `stateless_test.go`, `lan_test.go`, `conncap_test.go`, `bounds_test.go`: the listener (SNI certificates, routing, the `/mcp` alias, request-never-require, only a chain believed), the proxy headers, stateless MCP, the LAN guard, the connection cap and `CapBody`. `TestBodyCap` exercises `CapBody` on its own, with `httptest`, not through a TLS listener.
- `envelope_fuzz_test.go`: `FuzzSealedEnvelope`. `petname_local_test.go`: `TestNoPeerFacingSurfaceCanSetAPetname`.

## What it does not do

- It does not decide a budget. `Pool.Limit`, `PreOpen` and the node's `consumeBudget` ask the limits sidecar; the package only says which budget (`Charge`) and turns the answer into `rate_limited` or `unavailable`.
- It does not rate-limit per source address or for the node as a whole; that belongs to what stands in front of the node (SPEC.md §5.7, `ConnCap` comment).
- It does not fetch a URL a peer sends as media, and it does not serve the owner MCP's tools (it only provides `StatelessMCP` and `CapBody` for it).
- The transport identity is not authority over the owner surface; loopback is exempt from the LAN guard only because it grants a guest nothing here.
- The `Server` routes `/i/{token}` to an injected handler; the landing page itself is not in this package.
- It does not implement the envelope format or the open order; those are hdtp-identity's (`Decide`, `SealResult`, `OpenResult`) and HDTP §13.

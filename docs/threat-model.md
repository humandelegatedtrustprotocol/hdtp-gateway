# Threat model

What pact-gateway defends, against whom, and where the defence actually lives.
This is the reviewer-facing companion to SPEC.md §13, which is normative: §13
states the posture, this states the adversaries and points at the code and the
tests that hold each claim.

Read it with SECURITY.md's hardening-status table, which says what has **not**
been done yet. Nothing here has had independent cryptographic review.

## Assets

| Asset | Where it lives | Loss means |
|---|---|---|
| Account identity private key | `key_sealed` in the store, sealed at rest | Full impersonation of that identity to every contact. There is no revocation authority: recovery is a new identity and re-pairing everyone |
| Contact pins (SPKI per contact) | `contacts` table | Silent substitution of a contact — every later signature check passes for the wrong party |
| Message content and media | Store plus the media blob directory | Disclosure of private correspondence |
| Owner credentials (passkeys, bearer tokens) | `owners`, `tokens` | Full control of the node: it can message, book, and rewrite permissions as the owner |
| Integration credentials | `settings`, sealed at rest | Access to whatever third-party account was connected |
| Audit chain | `audit`, hash-chained | The ability to say truthfully what the node did |

## Adversaries

**A1 — Unauthenticated network caller.** Can reach the public listener and send
anything. Cannot present a pinned certificate or a valid signature. This is the
adversary the parsers meet first, before any identity is established, which is
why they are fuzzed (`FuzzEnvelopeWire`, `FuzzSealedPayload`).

**A2 — A pinned contact.** Legitimately paired, and now hostile. Holds a key the
node trusts, and can call every tool their permissions allow. The relevant
question is never "can they be stopped" but "can they act as *someone else*".

**A3 — A carrier: relay, edge terminator, tunnel provider, or the network.** Sees
and can drop, delay, reorder or replay traffic. On terminating deployments it also
terminates TLS. It is explicitly **not trusted**: a relay-delivered envelope runs
the same §4.4 open order as a direct one.

**A4 — A hostile invite counterparty, or anyone who can intercept the invite
fetch.** The owner is about to pin a key out of a document this adversary
controls (`FuzzInviteOffer`). Worth stating sharply, because it is the weakest
moment in the whole product: the invite landing is served by a node whose
certificate is its own self-signed identity key (SPEC §3.8), so that fetch has
**no transport authentication at all** — there is no chain to validate and no pin
yet, since learning the key is the point of the fetch. `verifyOffer` proves the
offer is internally consistent and signed; it cannot prove it came from the person
whose link the owner followed. An attacker positioned on that fetch can serve a
wholly self-consistent offer of their own. This is "card trust is channel trust"
(SPEC §13) at its sharpest, and confirming the fingerprint out of band is what
closes it.

**A5 — A compromised upstream MCP server.** An integration the owner connected,
returning hostile tool definitions or results.

**A6 — Local attacker with disk access.** Out of scope below.

## Trust boundaries

1. **Public surface → node.** Every caller is a fingerprint, proven by a TLS
   client certificate or an envelope signature, never by transport position
   (SPEC §3.5, §13.1). Where both proofs exist they must agree.
2. **Node → owner surface.** Separate mux, bearer token on every bind including
   loopback (`TestOwnerMCPRequiresATokenEvenOnLoopback`), passkey for the portal,
   CSRF on state change (`TestCSRFCookieOnGETAndEnforcedOnPOST`).
3. **Node → upstream integration.** Only tools the owner explicitly exposed;
   write-capable exposure takes a recorded acknowledgment.
4. **Account → account.** One node may hold several identities; nothing crosses
   (`TestAuditQueryNeverLeavesTheIdentitysAccounts`).

## Claims, and what holds them

| Claim | Held by |
|---|---|
| A message is attributed only to the holder of that contact's private key | `TestPinnedSenderPathAndSPKMismatch` — builds a real forgery claiming a contact's fingerprint while signing as somebody else |
| Tampering with a sealed header is detected | `TestAADTamperFails` — the protected header is the HPKE AAD |
| A contact cannot post into another contact's conversation | `TestAThreadCannotBeAdoptedByASecondContact` — thread ids are shared and caller-supplied |
| A pinned contact cannot rename itself | `TestRotationCannotRenameAPinnedContact` |
| The owner's own name for a contact is unreachable by peers | `TestNoPeerFacingSurfaceCanSetAPetname` — scans the peer-facing package |
| A key rotation is endorsed by the key being replaced | `TestUpdateContactVerifiedRotation` |
| A blocked contact learns nothing a stranger would not | `TestBlockedSenderIsNotAnOracle`, `TestBlockedCallerIsIndistinguishableFromAStranger` |
| A replayed envelope is acknowledged, never re-executed | `TestSealedReplayReturnsRecordedResult`, `TestReplayReturnsRecordedAck` |
| A relay cannot forge or misroute | `TestRelayRejectsForgedAndMisroutedEnvelopes` |
| Tier and permission gate every tool | `TestAllowExactTierAndPermission`, `TestBuiltinToolSurfacePerTier` |
| Rate limits apply on the real listener, not just in unit tests | `TestGuestRateLimitIsEnforcedOnTheRealListener`, `TestContactRateLimit60PerHour` |
| The audit chain detects tampering and survives pruning | `TestAuditTamperedExportDetected`, `TestAuditArchivePrunesAndKeepsTheChainVerifiable` |
| Parsers on untrusted input do not crash | Four fuzz targets, run in CI, kept honest by `TestEveryFuzzTargetRunsInCI` |

## Explicitly out of scope

These are decisions, not backlog (SPEC §13.2):

- **Forward secrecy at the envelope layer.** HPKE Base to a long-lived key: a
  later key compromise decrypts recorded traffic.
- **Metadata privacy against carriers.** A relay or edge sees who, when and how
  big. Sealed content stays ciphertext; the fact of a conversation does not.
- **Key loss.** No recovery authority. A lost key is a new identity.
- **Key separation.** One keypair serves TLS client, TLS server, HPKE recipient
  and signing (SPEC §2, §13). Accepted, documented, and the `kid` field is the
  reserved seam for changing it. A reviewer should expect to raise this.
- **Local attacker with disk access (A6).** Secrets are sealed at rest, but the
  sealing key is on the same machine. Disk encryption is the operator's job.
- **Malicious owner.** The owner is the trust root of their own node.
- **Denial of service by a determined network adversary.** Rate limits and input
  caps blunt abuse; they are not DoS protection.
- **Impersonation by name.** A contact chooses the name on its card, and two
  contacts may legitimately share one. Names are capped, control- and
  bidi-stripped, and cross-script confusables are folded for collision detection,
  with the fingerprint shown on any collision — but the durable answer is the
  petname, which no peer can reach. Within-Latin look-alikes (`l`/`I`/`1`,
  `rn`/`m`) are a known gap.

## Where a reviewer should start

1. `internal/public/identify.go` — `OpenSealed`, the numbered open order of
   SPEC §4.4. Order is load-bearing: addressing, then kid, then open, then
   signature, then the unified identity rule, then freshness, then replay.
2. `internal/envelope/` — the HPKE Base + detached signature construction, with
   the protected header as AAD. Test vectors in `testdata/vectors.json`.
3. `internal/core/policy/` — Cedar authorization, four call sites (three filter
   `tools/list`, one gates the call and re-resolves the tier).
4. `internal/core/audit/` — the hash chain and its archive/prune path.

# Threat model

What pact-gateway defends, against whom, and where the defence actually lives.
This is the reviewer-facing companion to SPEC.md §13, which is normative: §13
states the posture, this states the adversaries and points at the code and the
tests that hold each claim. The protocol it implements is PACT 2.0.0: the
person's self-signed root is the identity, the host holds a leaf that root
issued it, and a chain is what proves anything.

Read it with SECURITY.md's hardening-status table, which says what has **not**
been done yet. Nothing here has had independent cryptographic review.

## Assets

| Asset | Where it lives | Loss means |
|---|---|---|
| Account **leaf** private key | `leaves.key_sealed` in the store, sealed at rest | Impersonation of that identity **until the leaf expires or is renewed**. A leaf lives at most 398 days, and the newest leaf at the pinned endpoint outranks the stolen one with every contact it reaches (PACT §14.3). The thief cannot issue itself another: that takes the root |
| The **root** private key | Not here. The person's wallet (PACT §9) | The identity itself, fought over by two holders, with no authority to appeal to (PACT §14.5). It is deliberately out of this node's custody |
| Contact pins (a root fingerprint, the endpoint, and the latest leaf accepted) | `contacts` table | Silent substitution of a contact — every later chain check validates for the wrong party |
| Message content and media | Store plus the media blob directory | Disclosure of private correspondence |
| Owner credentials (passkeys, bearer tokens) | `owners`, `tokens` | Full control of the node: it can message, book, and rewrite permissions as the owner |
| Integration credentials | `settings`, sealed at rest | Access to whatever third-party account was connected |
| Audit chain | `audit`, hash-chained | The ability to say truthfully what the node did |

## Adversaries

**A1 — Unauthenticated network caller.** Can reach the public listener and send
anything. Cannot present a pinned certificate or a valid signature. This is the
adversary the parsers meet first, before any identity is established, which is
why they are fuzzed (`FuzzSealedEnvelope` drives arbitrary bytes through the whole open).

**A2 — A pinned contact.** Legitimately paired, and now hostile. Holds a key the
node trusts, and can call every tool their permissions allow. The relevant
question is never "can they be stopped" but "can they act as *someone else*".

**A3 — A carrier: edge terminator, tunnel provider, or the network.** Sees and can
drop, delay, reorder, replay — **and answer**. On terminating deployments it also
terminates TLS, so in edge mode the carrier is a MITM by construction, not a
position an attacker has to reach. It is explicitly **not trusted**, and the
containment is stated in four parts: content is sealed past it; the sender's
identity rides inside the ciphertext, so it sees `kid` and timing but not who
sent what (PACT §13.2); an answer it forges in plaintext is refused by the caller
unless it carries one of the few codes a node can legitimately reach *before*
opening an envelope; and a refusal it might have read is sealed, so it cannot
tell whether the recipient pins this sender. What it keeps is metadata and
availability.

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

**A7 — A former host.** Held the identity's leaf and all its data until the person
moved. Its leaf is still valid until it expires. It can still answer at the old
address, and it knows every contact. What it cannot do: issue itself a new leaf,
follow the person to the new address, or keep a contact that has seen the newer
leaf — PACT §14.3 is what makes leaving safe, and PACT §9 requires the vacated
address not be reassigned until the last leaf for it has expired.

**A6 — Local attacker with disk access.** Out of scope below.

## Trust boundaries

1. **Public surface → node.** Every caller is the **root of a chain that
   validated** (PACT §14.2), proven by presenting that chain as the TLS client
   certificate or by carrying it inside a sealed envelope — never by transport
   position (SPEC §3.5). Where both proofs exist their leaf keys must agree. A
   lone self-signed certificate is neither proof: it names no root, and anyone
   mints one in a second.
2. **Node → owner surface.** Separate mux, bearer token on every bind including
   loopback (`TestOwnerMCPRequiresATokenEvenOnLoopback`), passkey for the portal,
   CSRF on state change (`TestCSRFCookieOnGETAndEnforcedOnPOST`) — the double-submit
   token AND where a browser says the request came from (`Sec-Fetch-Site`, else a
   foreign `Origin`), because the token cookie is readable by a page on any other
   port of the same host (`TestEveryMutatingPortalRouteRefusesAForgedRequest`, over
   every mutating route the portal registers). No answer lets another origin read it
   (`TestNoPortalAnswerAllowsAnotherOrigin`). Owner-MCP bodies are capped at 1 MiB
   (`TestBodiesPastTheCapAreRefusedByTheBytesThatArrive`).
3. **Node → upstream integration.** Only tools the owner explicitly exposed;
   write-capable exposure takes a recorded acknowledgment.
4. **Account → account.** One node may hold several identities; nothing crosses
   (`TestAuditQueryNeverLeavesTheIdentitysAccounts`; every owner-MCP tool that takes
   an account answers another identity's as it answers none,
   `TestTheOwnerMCPNeverReachesAnotherIdentity`; every portal route refuses an
   account its owner does not administer, named in the query or the form, and
   audits it, `TestAnotherOwnersAccountIsNotFoundAndTheRefusalAudited`; a web
   wallet's answer installs only for the request that minted its state,
   `TestAWalletAnswerCannotCrossIdentitiesOrEndpoints`). In v1 every owner is
   granted every account (internal/identity/membership.go), so these hold a
   boundary a token narrowed to one account, and a later non-admin owner, rely on.

## Claims, and what holds them

| Claim | Held by |
|---|---|
| A contact cannot post into another contact's conversation | `TestAThreadCannotBeAdoptedByASecondContact` — thread ids are shared and caller-supplied |
| A pinned contact cannot rename itself | `TestACardRefreshCannotRenameAPinnedContact` |
| The owner's own name for a contact is unreachable by peers | `TestNoPeerFacingSurfaceCanSetAPetname` — scans the peer-facing package |
| A blocked contact learns nothing a stranger would not | `TestBlockedCallerIsIndistinguishableFromAStranger` |
| A replayed envelope is acknowledged, never re-executed | `TestSealedReplayReturnsRecordedResult` |
| Tier and permission gate every tool | `TestAllowExactTierAndPermission`, `TestBuiltinToolSurfacePerTier` |
| Rate limits apply on the real listener, not just in unit tests | `TestGuestRateLimitIsEnforcedOnTheRealListener`, `TestEveryBudgetIsRefusedUnavailableWhileTheSidecarIsDown` |
| The audit chain detects tampering and survives pruning | `TestAuditTamperedExportDetected`, `TestAuditArchivePrunesAndKeepsTheChainVerifiable` |
| Parsers on untrusted input do not crash | Four fuzz targets, run by `make fuzz` in the pre-push gate, kept honest by `TestEveryFuzzTargetRunsUnderMakeFuzz` |
| Only a chain that validates names a caller; a lone certificate names nobody | `TestHandshakeAcceptsEveryCertificateAndBelievesOnlyAChain`, `TestClientCertRequiredTakesAChainAndNothingElse` |
| A refusal past the open is sealed, so a carrier cannot tell a pinned sender from a stranger | `TestARefusalPastTheOpenIsSealed` |
| A carrier's forged plaintext answer is not the peer's answer | `TestAPlaintextRefusalPastTheOpenIsNotThePeersAnswer` |
| A key-pinned server is not an identity; the chain to the pinned root is | `TestASelfSignedServerCertificateIsNotAnIdentity`, `TestChainAsServerCertificateValidatesToThePinnedRoot` |
| Chain confusion, leaves and envelopes outside their time, forged headers and the retired generation are all refused — offline in both ports at the exact boundaries, and live against a running node, with one control that a receiver refusing everything fails | `pact-identity/js/intrude.mjs` (132 scenarios, offline, measured 2026-09-27); `pact vectors intrude --against` and `pact-identity/js/live.mjs` (the same 28, one list both drivers read, `js/live-scenarios.json`; 28 blocked by this node and by the hosted platform, 2026-09-20) |

## Explicitly out of scope

These are decisions, not backlog (SPEC §13.2):

- **Forward secrecy at the envelope layer.** HPKE Base to a long-lived leaf key:
  a later compromise of that key decrypts traffic recorded while it was current.
  Bounded by the leaf's 398-day ceiling and by renewal, not fixed.
- **Metadata privacy against carriers.** An edge sees `kid` — which names the
  RECIPIENT's leaf key — along with timing and sizes. It no longer sees who sent
  a message: the sender's chain rides inside the ciphertext (PACT §13.2). Sealed
  content stays ciphertext; the fact of a conversation does not.
- **Root loss.** No recovery authority, and the root is not on this node. A lost
  root is a lost identity (PACT §9). A lost *leaf* is not: the wallet issues
  another (SPEC §3.9).
- **Key separation.** One **leaf** keypair serves TLS client, TLS server, HPKE
  recipient and signing (SPEC §2.5, §13). PACT §13.5 bounds it: that key signs
  exactly four structures, each distinguishable by its first bytes, and nothing
  else. Accepted, documented, and `kid` is the reserved seam for changing it. A
  reviewer should expect to raise this.
- **Local attacker with disk access (A6).** Secrets are sealed at rest, but the
  sealing key is on the same machine. Disk encryption is the operator's job.
- **Malicious owner.** The owner is the trust root of their own node.
- **Denial of service by a determined network adversary.** Rate limits and input
  caps blunt abuse; they are not DoS protection.
- **A root fought over by two holders.** PACT §14.5 records this as residual: if
  a thief has the root, both parties can issue leaves and the newest one wins with
  whichever contact it reaches first. The defence is a root that is never at rest
  — in a hardware key, or derived from a passkey on each use — which is the
  wallet's business and outside this node.
- **Impersonation by name.** A contact chooses the name on its card, and two
  contacts may legitimately share one. Names are capped, control- and
  bidi-stripped, and cross-script confusables are folded for collision detection,
  with the fingerprint shown on any collision — but the durable answer is the
  petname, which no peer can reach. Within-Latin look-alikes (`l`/`I`/`1`,
  `rn`/`m`) are a known gap.

## Where a reviewer should start

1. `internal/public/decide.go` — `decideEnvelope` and the pin checks around it.
   The open order is PACT §13.3's and is load-bearing: version and suite, then
   `kid` against the keys this endpoint holds, then HPKE-open, then the signature
   under the chain's leaf, then the tier, then freshness, then replay. The
   decision itself is the library's pure `Decide`; this file is the seam that
   supplies the node's state and applies the effects.
2. `internal/public/listener.go` and `internal/outbound/client.go` — what the
   transport is allowed to prove, in both directions. Both were wrong in the same
   way on 2026-09-18 and both now accept only a validated chain.
3. `pact-identity/` — chain validation and the certificate profile, with the
   shared vectors in PACT Appendix B and the intrusion battery over both ports.
   Nothing in this repository re-implements §14.2, and nothing reaches for a
   general X.509 path validator.
4. `internal/core/policy/` — Cedar authorization, four call sites (three filter
   `tools/list`, one gates the call and re-resolves the tier).
5. `internal/core/audit/` — the hash chain and its archive/prune path.

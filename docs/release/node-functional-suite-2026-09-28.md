# One end-to-end suite and one attack suite, for the node and the cloud (2026-09-28)

The owner's requirement: "same as pact-cloud, have suite of tests which are functional and can be
adopted in gateway have them in pact-gateway as well along side the testing suite. we want to make
sure both are 100% properly tested and safe before releasing." Clarified the same day: "basically
both are one in the same thing. I want e2e tests and attack vector tests specifically."

So the node and the cloud are one product speaking one protocol. The plan below builds ONE
definition of each suite and runs it against every target (a node, the cloud, staging), and keeps
the doors that exist on only one host in an explicit divergence list that a test holds (build rule 1).

This page is the map (part 1), the design (part 2), and the build plan with its status (part 3).
It was written before any code, from `origin/main` of each repository: node `d039bbe`, cloud
`bd474f0`, pact-identity `c486047`.

## 1. The map: what exists, and whether it applies to the node

### 1.1 What the two hosts share, and what they do not

What the hosts share is **the wire**: the public MCP surface at an identity's endpoint, sealed
envelopes (§13), the chain (§2, §14), the guest, pending and contact tiers, the invite landing
(§4), and the error vocabulary. Every attack suite that speaks the wire can run against both hosts
unchanged, given a target.

What they do not share is **the owner's doors**:

| | Node | Cloud |
|---|---|---|
| Owner API | `/owner/mcp`: flat tools (`approve_contact`, `create_invite`, `get_inbox`, `audit_query`, ...), one bearer token per owner | `/v1` REST with agent keys, plus `/mcp?identity=` router tools (`pact_contacts_change` `{action, arguments}`) |
| Portal | a Go SPA on the internal listener (loopback or `InternalHost`), passkey plus a double-submit CSRF cookie | the Worker portal, WorkOS session, workspaces |
| Export and import | the CLI (`pact-gateway export` / `import`), with the node stopped | `/v1` export zip; import through the portal's wallet |
| Renew, move, sign | `account csr` plus `install-leaf`, or the portal's wallet (`/identity/{slug}/wallet` to the wallet's `/sign`) | the portal relays a wallet request |
| Identities | `account create` over the admin socket, certified by a wallet | WorkOS user, workspace, `claimIdentity`, wallet ceremony |
| Card over HTTP | `/card.vcf` on the portal (owner-side); peers get it from the `get_card` tool | `https://<host>/<slug>/card.vcf`, public |
| Invite landing | `/i/<token>` at the host root | `/i/<token>` under the identity's address |

SPEC §4 places the invite at "a path segment on the issuer's host — `/i/<token>`", and no SPEC
section requires a public `card.vcf`. So the two address layouts are both conformant: they are
target parameters, not findings.

### 1.2 The cloud's suites

| Suite | What it is | Applies to the node? |
|---|---|---|
| `gateway/e2e/pair.mjs` + `tables/scenarios.mjs` (95 scenarios, 8 subcases), the `calls*.mjs` tables | Two or three identities on staging, driven through `/v1`, the router MCP and the portal DOM | **Adapted.** About 45 scenarios are protocol journeys (invite, accept, reject, self-invite, messages, media, permissions, block/unblock/remove, card, export/import, renewal, move). About 36 are cloud-platform only (workspaces, plans, billing, promos, members, webhooks, SSO and residency, custom domains, sessions, OAuth AS, edge). The driver is hard-wired to WorkOS, `/v1` and the portal and cannot drive a node. What carries over is the **journey list**, which becomes the shared definition (2.2). |
| `e2e/identity.mjs` / `make e2e-staging` | One identity end to end (WorkOS user, workspace, wallet ceremony over CDP with a PRF authenticator, agent key), then the Go battery against it | **Adapted.** The node's equivalent is `World.Node` (passkey wizard, certify, owner token); the battery half is 2.1. The wallet half is 2.4. |
| `e2e/ceremony.mjs` / `make wallet` | The real wallet page, served from a Node http server with an in-memory relay; eleven sections including `/sign` from a loopback STUB node | **Yes, against a REAL node.** Its section 5b drives `/sign` from a stub; 2.4 drives it from the node's portal. |
| `gateway/conformance` (the Go battery, 55 live subtests plus 9 certificate subtests) | The wire, driven through the node's own `internal/outbound` client; controls for the guest negatives, the envelope negatives and the budget | **Yes, with a target.** As written it only reaches the cloud: it builds `https://host/slug`, reads `card.vcf` at the endpoint, trusts only WebPKI, and drives the cloud's router MCP as its owner. 2.1 gives it a target. |
| `pact vectors intrude --against` (pact-identity, 28 live scenarios in `js/live-scenarios.json`, control last, fresh attacker keys every run, UNREACHED on `http_*`) | Envelope, chain, time and header forgeries against a live host | **Yes, unchanged.** It is already one definition with no host in it. Nothing runs it against a node. |
| `test/public-surface*.test.ts`, `guest-budget`, `invite-landing`, `client-refusal`, `request-contact` (vitest in workerd) | The cloud's wire refusals, hermetically | **No, as themselves**: they call the Worker. The node's counterparts are its Go tests (`internal/public`, `docs/conformance.md` maps each clause to one). The shared live form is the battery and intrude. |
| `scripts/check-no-keys.mjs`, `check-no-import.mjs`, `check-key-boundary.mjs` | Static text guards over the cloud's source | **No**: they are about the Worker's module layout. The node's equivalents are its own static guards (`no1x`, `nohandsql`, `layering`, `wholechain`). |
| The `staging-*.test.ts` table guards | Hermetic: every call in the tables names a real route or action | **Adapted**: the journey list gets the same kind of guard on both sides (2.2). |

### 1.3 The node's suites today

| Suite | Covers |
|---|---|
| `make check` (`internal/...`) | unit and integration tests; `internal/public` refusals; `internal/portable` with the pact-identity hostile export corpus (`TestTheCorpusIsImportedAsTheCoreReadsIt`, at least 30 cases); fuzzing of four parsers; the doc gates (`docs/conformance.md` cites real tests) |
| `make harness` (hermetic) | the harness's own guards: registry, images, ports, certify |
| harness live tiers | F1–F5 (fabric; F5 is the guest tier over real mTLS), S1–S4, S7–S17, T5–T7 (`docs/harness-design.md` §4) |

The node's journeys already built: first run and the wizard (S1), pairing (S2, S12), reject and
unblock (S13), messages both ways (S14), media under the fetch guard (S3), a stranger and a narrowed
contact refused (S9), a move campaign (S10), export and import onto a new host (S16, S17).

### 1.4 The gaps

Attack vectors not run against a node at all:

1. The 28 live intrusion scenarios (forged, expired, replayed envelopes, chain shapes, a key-pinned card) — only offline, against the ports.
2. The Go battery's 64 live subtests (the guest tier, `chain_required`, the budget with its second-root control, invite no-oracle 404s, replay of a redeem, audit hashing) — only against the cloud.
3. The node's own doors under attack: CSRF on the portal and the wallet's install (foreign origin, `Origin: null`, repeated fields), wallet-return replay and state reuse, a chain from the wrong root, owner tokens reaching another account, oversized bodies on the owner surface.
4. The hostile export corpus through the REAL door (the `import` command in the shipped image), not only the package.

Journeys not run against a node: self-invite, a revoked or used-up invite, auto-accept, remove,
leave, owner-token scope, the real wallet page's `/sign` from the node's portal (the harness's wallet
is a Go stub), and media plus review-then-confirm through an export round trip.

## 2. The design

### 2.1 Attack suite: the two wire batteries, parameterised by target

- **Intrusion** (`pact vectors intrude`): one definition already. A harness scenario stands a
  node up, takes its card from the owner's `export_card` tool, and runs
  `pact vectors intrude --against <endpoint> --card <file> --allow-insecure`. Its verdicts
  (CONTROL REFUSED, REPRODUCES, UNREACHED) fail the scenario.
- **The Go battery** gets a `Target`: the endpoint URL whole, where the card comes from, where
  invites land, how TLS is trusted (WebPKI for the cloud, pinned to the card's leaf for a node), and
  an owner adapter with two implementations (the cloud's router MCP, the node's `/owner/mcp`). A
  transport failure becomes UNREACHED, never a finding. Cases that do not apply to one target are
  skipped from ONE list (`divergence`), each entry naming a real subtest and a reason, held by a
  hermetic test; no other code skips by target. A harness scenario runs the battery against a
  live node through a `go.work` (the pattern `make dependents` uses), with the battery's checkout
  declared as a Need so a tier says NOT PROMISED rather than skipping.

### 2.2 E2E suite: one journey list, a driver per host

The drivers cannot be one program (the node has no `/v1`, the cloud has no `/owner/mcp`), so the
single definition is the **list of journeys**: `harness/journeys/journeys.json`, each with an id and
a name, the node harness scenarios that prove it and the cloud pair scenarios (or driver files) that
do, or, for a host with none yet, why (`node_pending`, `cloud_pending`):

- node: `harness/journeys` holds every node entry to a scenario the registry scans, and an empty
  one to a reason;
- cloud: `gateway/e2e/tables/journeys.json` is a byte-identical copy, held to the node's by the
  node's guard when the sibling is checked out (the 1.x markers' pattern), and `test/journeys.test.ts`
  holds every cloud entry to a pair scenario or a driver file.

### 2.3 The node's own doors under attack

Hermetic, in `make check`, against the real handlers (`httptest`): CSRF and CORS on the portal and
the wallet install, repeated and `__proto__` fields, wallet-return replay and state reuse, a chain
from the wrong root, owner tokens across accounts (a 404-shaped refusal, never another account's
data), the owner surface's body cap. Each attack has a control that must get through.

### 2.4 The wallet, for real

A harness scenario serves the cloud's REAL wallet page (the one `make wallet` serves) beside a node,
and drives the node's portal to `/sign`, the passkey (a PRF virtual authenticator), the return and
the install, then a replay of the return.

### 2.5 Tiers

| Tier | What runs |
|---|---|
| hermetic (`make check`, `make harness`) | 2.3; the divergence and journey-list guards; the battery's offline seal test; the recipe guards |
| live local (`harness-pr`, `harness-nightly`) | intrusion and the battery against a node; the journeys; the corpus through the image; the real wallet |
| staging (owner's) | the battery and intrusion against staging (`make -C pact-cloud conformance`, `ship-staging`); node ↔ cloud export and import |

## 3. Build plan and status

Each item: built, mutation-checked (red on broken code), gated, pushed, PR opened; not merged.

| # | Item | Repo, branch | Tier | Status |
|---|---|---|---|---|
| B1 | This map and plan | node `test/node-functional-suite` | — | done |
| B2 | Intrusion against a live node: S18 | node | nightly | done: 28 of 28 blocked, the control through, 28 refusal rows; red on an image that stops auditing envelope refusals and on one that answers `unavailable` |
| B3 | The battery's `Target` and divergence list | cloud `test/battery-targets` | hermetic + staging | done; the cloud path of the changed battery is not yet run against any cloud (see 3.3) |
| B4 | The battery against a live node: S19 | node | nightly | done: 77 of 77 after the fixes in 3.1 |
| B5 | The node's doors under attack (2.3) | node `test/node-door-attacks` | hermetic | in progress |
| B6 | The node's missing journeys (S21) and the shared journey list | node + cloud | hermetic + nightly | done: `harness/journeys/journeys.json`, 25 journeys; its cloud copy `gateway/e2e/tables/journeys.json` on `test/battery-targets` |
| B7 | The hostile corpus through the shipped image: S22 | node | nightly | done on the v0.3.2 corpus; see 3.2 for v0.3.3 |
| B8 | The real wallet page from a node: S20 | node, with pact-cloud `test/local-cloud-target` | nightly (needs the local cloud) | done: L1, L5, L6 PASS; L5 red on a node that installs a replayed return |
| B9 | Every early refusal of the public tools audited | node | hermetic | done |

### 3.1 What the suites found on node `main`, and the fixes

| Finding | Found by | Fix |
|---|---|---|
| A stranger whose leaf names a pinned contact's address redeemed an auto-accept invite and became a contact (PACT §5.2 says never) | S19, contact group | the core's `address_claim` rides on the proof; the store answers the same rule for a certificate-proven guest; the two held equal by `TestTheTwoAddressClaimsAgree` |
| `create_invite` answered a bare token, no link to hand out | S19, invite group | the owner MCP answers `url` on the public origin |
| Every public caller's audit row was written as the node's own (`system`) | S19, audit group | sealed_call and the built-in tools write `guest` or `contact` |
| Thirty early refusals (decode, caps, vocabulary) and a non-envelope `sealed_call` body wrote no audit row | reading the code S18 exercises | `ToolDeps.refuse`; `TestEveryMalformedCallIsRefusedAndAudited` |
| An owner's own invite made them their own pending contact, and any redemption the peer refused as a tool error was recorded `pending_out` | S21 | the initiator refuses the identity's own offer, and a tool-error answer is a refusal with nothing recorded |
| The address claim was not shown to the owner (SPEC §5.2's second half) | reading the first fix | the Requests tab and `list_contacts` name the contact whose address a request comes from, derived at read time |
| After a move, doctor told the owner to have the wallet sign again for imported contacts the new leaf's campaign owed; the install notice said `account announce` | S20 (pact-cloud's live-local L5), then e2e-suite-staging's L5 | first `HandshakesTried` (the walk's progress rows), which read differently either side of the walk; now `HandshakesUnderWay` (the ledger: `Campaign.Owes`), which the walk does not change |
| `TestSubscribeInboxReceivesResourceUpdated` and `TestP2ExitPortalPairing` flaked under load | the gate | fixed on main by PR #11 (the tests wait for the server to hold the subscription); this branch's own fixes were dropped at the merge in favour of #11's |

### 3.2 The v0.3.3 and v0.3.4 corpus (SPEC 2.2.2 and 2.2.3, 44 cases)

v0.3.4 is this round's final pact-identity release (the same API as 0.3.3, 44 corpus cases). S22
reads the corpus of the version the harness requires, and `make identity-bump VERSION=0.3.4` moves
the node and the harness together, so S22 runs the v0.3.4 corpus through the image of the tree
that bumped. No node branch was on v0.3.4 when this was written; the measurement below is the
v0.3.3 corpus's.


S22 run with the harness on pact-identity v0.3.3 against an image of node `main` (v0.3.2): 27 of its
44 cases fail, all on one change of format — a v0.3.3 export no longer lists media in the manifest's
`files` — so main refuses both valid files (and with them the wrong-owner control, whose identity a
valid file makes), refuses 24 hostile files in other words than the corpus's, and lets
`media-listed-in-files.zip` through. (The commit that added S22 said "misreads 29"; this is the
measured count.) The node's move to v0.3.3 (in progress on `fix/review-2026-09-28`) carries it;
the harness moves with it by `make identity-bump`, and S22 is re-run then. Until then a v0.3.3
export — from a cloud on v0.3.3 — cannot be imported into a node on main.

### 3.2a The cloud, locally (pact-cloud `test/local-cloud-target`, PR #93)

`make -C pact-cloud e2e-local` stands the real gateway Worker up under workerd and runs L1–L7 against
it: 7 of 7 PASS on its run of record. What each measured, and what it did not:

- L3, the changed battery against the cloud: 78 passed, 0 failed, two skips excused by name (the
  stale kid, which no cloud journey can produce; the calendar, which a new identity has none of).
  It needed two battery fixes, on #93: an extra trusted root, and `rate_limited` outside the budget
  case read as UNREACHED.
- L4, `pact vectors intrude`: 28 of 28 blocked, the control through.
- L2, the relay, the vault store and `POST /sign` through their real routes: every cross-site form
  refused, each group's control through.
- L7, the v0.3.4 corpus through the cloud's HTTP import door: all 44 refused and nothing changed,
  but **17 reached the check they exist for and 27 did not**: those 27 were refused as another
  identity's export, at the owner gate, because the corpus is built under one fixed root (a
  labelled seed in pact-identity's `exportcorpus`) and a cloud identity's root comes only from a
  passkey. They are UNREACHED for their own checks, and held there only by the Worker's own tests.
- S19 with #93's battery against the node: 78 of 78, nothing skipped.

### 3.3 Open, and tracked

- **MCP 2026-07-28 on the node's public surface.** The node answers `server/discover` in the 2026-07-28 shape but offers up to 2025-11-25, because the go-sdk offers 2026-07-28 only over a stateless Streamable HTTP transport and the public surface is stateful (per-session transport facts). The battery lists it as divergent for a node. Whether to move the public surface to a stateless transport is the owner's decision; it is not taken here.
- **The changed battery has run against a local cloud (3.2a), not staging.** Staging, after the owner's ship: the battery (`make -C pact-cloud conformance` with a token), `pact vectors intrude --against` the staging identity, `make e2e-pair`, and node ↔ cloud moves.
- **Merge order**: pact-cloud #92, then #93 (which stacks on it and carries two battery fixes), then this node PR. This PR and #9 (door attacks) both touch `internal/public`: whichever merges second is rebased and runs the nightly tier again.
- **Interop hazard**: a v0.3.3+ export (media no longer in the manifest's `files`) cannot enter a node on v0.3.2. If the cloud's identity bump reaches production before the node's, a cloud → node move fails at import. After the node moves to v0.3.4 (`make identity-bump VERSION=0.3.4`, which moves the harness too), `cd harness && go run ./cmd/harness run -id S22` runs the v0.3.4 corpus through the image.
- **pact-identity**: `pact vectors intrude` scores a `rate_limited` answer as REPRODUCES, or the control's as CONTROL REFUSED, where it never reached the layer under test (found by the local cloud's L4 under the edge's limit). It belongs with UNREACHED; not fixed here (pact-identity is not in this change).
- **Owner decisions**: a stateless public surface for MCP 2026-07-28; `permission_denied` versus a not-found answer on the owner MCP for another identity's account (PR #9 kept `permission_denied`, identical for both, so it leaks nothing); the `node_admin` flag of SPEC §3.3 for non-admin owners.
- **DNS rebinding proper** (a name answering public, then private): the fetch guard vets every resolved address and pins the dial to it (`messaging.MediaService.Fetch`); S3 holds the name-that-resolves-private case and the IPv4-mapped literal, not a resolver that changes its answer between two lookups.

Needs staging (the owner deploys): the battery and intrusion against `stg`, node ↔ cloud export and
import, the cloud's journeys through `make e2e-pair`.

Known before starting: a passkey registered by the setup wizard cannot sign the owner in again
(residentKey not required), found by the QA run and fixed on `fix/passkey-discoverable`; this work
does not re-fix it.

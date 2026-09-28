# MCP stateless and horizontally scalable, and the unauthenticated surface bounded

Owner, 2026-09-28: "make sure the MCP is stateless and horizontally scalable", and, of the guest
surface, "want to make sure that we're not leaving a surface open for DDOS attack".

Status: **approved 2026-09-28** (D1 stateless, D2 Postgres AND SQLite, D3 Worker answers, D4 accept and
publish).

## 0. What is measured today

Two read-only surveys, both on 2026-09-28: cloud `feat/fair-rate-limits` at bacf453, node main at
744de15. Every item below carries its file:line in the survey reports; the headings here are the
findings.

**Cloud: both MCP endpoints are already stateless.**
- The per-identity `POST /<slug>` and the owner `/mcp` issue no session. They serve POST only, with
  405 otherwise, and do not require `initialize`.
- Cross-call state is in explicit handles: sealed MRTR `requestState`, confirmation records in the
  Tenant DO.
- Any Worker instance behaves the same.
- The ceiling is ONE Identity Durable Object per identity. On staging after the pin-candidates fix
  (2a54c08), a single identity holds:
  - `send_message`: 40/s at 300 contacts and at 2000 contacts. At 2000 contacts it is slower at
    every rate, so O(contacts) residue remains on the send path (being found now);
  - `get_card`: 100/s at 300 contacts.

**Node: both MCP endpoints are stateful go-sdk sessions.**
- `node.go:1170-1206`: `Stateless` unset. The owner MCP has a `MemoryEventStore`
  (`compose.go:312`).
- Consequences:
  - it cannot serve MCP 2026-07-28, which the SDK serves only when stateless;
  - it refuses modern requests with -32022;
  - the node lags PACT SPEC §7's "current MCP spec".
- Eleven kinds of process-local state stop two node processes sharing one database:
  1. the data-dir flock;
  2. the session map and SessionBinder;
  3. the event store and subscriptions;
  4. the in-memory Bus (`wait` and the inbox never wake for another instance's writes; `wait`
     returns the process clock as its cursor);
  5. the agent-answered waiters;
  6. the in-memory rate limiter. N instances grant N× the budget, and its numbers are not §12's;
  7. the audit writer's in-memory head. A second writer collides on `seq`, and per §5.8 that
     instance then stops answering;
  8. accounts, keys and certificates loaded at start;
  9. the per-caller Pool cache;
  10. background loops with no claim (duplicate retries);
  11. local-disk blobs and keyring.

**The unauthenticated surface** (the DDoS audit), worst first:
1. cloud `/oauth/token`: no limiter, and an outbound fetch to a caller-chosen URL;
2. fresh-root guest floods: full crypto before any limit, a free key per call, uncapped
   `pending_in`, and ack rows kept up to 30 days;
3. the node listener: no timeouts, no connection cap, sessions that never expire, no per-IP or
   global limit;
4. hosts outside the WAF expression: the apex, custom hostnames, staging `*-stg.pact-cloud.com`;
5. unsealed MCP methods on the cloud wake the object and skip SEALED_LIMITER, and `tools/list`
   writes an audit row;
6. vault PUT fill;
7. `/auth/callback` replay drains the WorkOS quota;
8. a signature per invite-landing view; `/sign` unlimited; the Stripe body uncapped.

**Conformance found on the way:**
- ack retention is sender-chosen (`exp`) on both systems. SPEC §13 requires
  `min(exp, ts+300 s)`;
- plain `tools/list` spends no budget on either. SPEC §12 says it must.

## 1. Decisions for the owner

| # | Question | Recommendation |
|---|---|---|
| D1 | Node MCP goes stateless (2026-07-28), dropping sessions, `tools/list_changed` over SSE, the owner MCP's event store and resource subscriptions | **Yes.** Clients re-list tools. The owner `wait` tool stays, reading the store's cursor. Owner resource updates go through `subscriptions/listen` if a client needs pushes; not built until one does. |
| D2 | Which node deployments are horizontally scalable | **Owner: both Postgres and SQLite.** Postgres: many processes on many hosts behind one load balancer. SQLite: many processes on ONE host sharing the data dir (WAL, `busy_timeout`, `BEGIN IMMEDIATE` for writes). SQLite's locking is not safe over a network filesystem, so SQLite across hosts is not claimed, and the docs say exactly that. |
| D3 | Where the cloud answers `initialize`, `ping`, `server/discover` and notifications | **In the Worker**, never waking the object. The pause state and "has a live leaf" are copied into the KV route. KV lags by up to ~60 s, so a paused identity keeps answering these CONSTANT, data-free methods for up to a minute; every tool call still stops at once in the object. `tools/list` stays in the object, charged and audited per §12. |
| D4 | One identity's ceiling on the cloud | **Accept one object per identity.** Measure it and publish it as the per-identity limit (IDENTITY_CAPACITY_PER_SECOND). Sharding one identity means splitting the audit chain (SPEC §11): a protocol-level change, not in this plan. |

## 2. The work, in order (each item committed, gated and pushed before the next)

### Cloud (`tech-sumit/pact-cloud`, on feat/fair-rate-limits, then a follow-up branch)

- **C1** Remove the remaining O(contacts) on the send path. Measured locally at 1/300/2000
  contacts, then on staging.
- **C2** Metadata methods answered in the Worker (D3). The route carries `serving` and `leaf_live`,
  written where pause and leaf install already write the route. Also correct the legacy
  `initialize` claim `tools.listChanged: true`, since no stream carries it.
- **C3** A pre-crypto per-identity guest budget. The object charges `guest-total` (e.g. 60 per
  minute per identity) BEFORE the key unwrap and HPKE open, keyed on nothing the caller can
  rotate. Also: a cap on `pending_in` per identity; plain `tools/list` charged per §12; acks
  retained until `min(exp, ts+300 s)`; failures from `decide` charged to the source bucket.
- **C4** SEALED_LIMITER is charged for EVERY method at the per-identity door, not only
  `sealed_call`. The WAF expression is widened to the apex and to the staging identity host. For
  custom hostnames (Cloudflare for SaaS, on our zone), the Worker's edge limiter carries the load
  (the WAF rule cannot match them all on a Free zone's single rule).
- **C5** `/oauth/token`: CEREMONY_LIMITER keyed on the IP, failures from metadata-document fetches
  cached (negative, 5 min, query string stripped from the cache key), and the api host inside the
  WAF expression.
- **C6** Vault PUT, `/sign`, `/auth/callback`: limiter at each. The callback's state cookie is
  single-use. The Stripe webhook body is capped before the signature check.
- **C7** Invite landing signs once per leaf (the signature cached with the leaf).

### Node (`pact-cloud/pact-gateway`, after PR #15 lands)

- **N1** Listener hardening: Read, Write and Idle timeouts, a connection cap, a per-IP and a
  global token bucket in front of TLS chain validation and before any body is read.
- **N2** Stateless MCP (D1). `Stateless: true` on both handlers; SessionBinder, the owner event
  store and `ForwardBus` go; §12 limits advertised. Node SPEC §5, §8.5 and §11.4 are rewritten,
  and the §6 go-sdk version is corrected.
- **N3** Rate buckets in the store (a sqlc table, the cloud's `rate_buckets` shape), with §12's
  numbers, charged before the crypto. The same guest-total and `pending_in` cap as C3, plus the
  ack retention and the `tools/list` charge.
- **N0** The data-dir flock becomes a shared lock for `serve` (exclusive only for operations that
  must be alone: migrate, restore, erase). SQLite is opened in WAL mode with `busy_timeout`, and
  every write transaction is `BEGIN IMMEDIATE`. Migrations run under the exclusive lock, once.
- **N4** A shared change signal, one design for both engines: the store's change cursor, polled
  (short interval, the same cursor the cloud uses), with Postgres LISTEN/NOTIFY as a wake hint. It serves `wait`, the inbox, agent-answered waiters, presence,
  Pool invalidation and account/leaf reload. `wait` returns the store's cursor.
- **N5** The audit append re-reads the head in its transaction, serialised by an advisory lock on
  Postgres and by `BEGIN IMMEDIATE` on SQLite.
- **N6** Background loops claim rows (`SKIP LOCKED`) or hold a leader lease; blobs on configurable
  shared storage; the master key from the environment for multi-instance.
- **N7** Proof: a harness scenario running TWO node processes behind a round-robin proxy, once on
  one Postgres and once on one SQLite data dir. A legacy client and a 2026-07-28 client both complete: redeem → send →
  owner `wait` wakes on the other instance → retry is not duplicated → the audit chain verifies.
  With a control: the same scenario with N5 reverted must fail.

### Protocol

- **P1** None required: SPEC §7 already asks for the current MCP spec. SPEC §12 and §13 are
  already right; the implementations move to them.

## 3. Verification

- **Cloud:** `make check`. Staging:
  - `load-staging` for `send_message` and `get_card` at 300 and 2000 contacts;
  - a flood run: fresh roots at 10× the guest-total budget must be refused BEFORE the crypto
    (measured as object CPU per refusal), with one control that must get through;
  - `e2e-pair`, `e2e-suite-staging`, `e2e-staging`.
- **Node:**
  - `make check`, `analyze`, `sqlc-check`, `harness`;
  - `harness-nightly` with N7;
  - a flood run against the node listener, with a control.
- Every new guard is mutation-checked.

## 4. What this plan does not do

- It does not shard one identity across objects (D4).
- It does not make SQLite multi-HOST (D2): one host, many processes.

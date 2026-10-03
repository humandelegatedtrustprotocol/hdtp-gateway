# Rate limits in two layers: the Cloudflare edge, then a Rust middleware

Owner, 2026-09-28:
- "no rate limit to be implemented on code level but it should be ideally managed on infra level i.e
  on cloudflare level if not possible then we can add a proxy container before server/endpoint which
  does this management of rules";
- "we can define a middleware which does checks. envelope will be opened at this middleware based on
  the identity, this middleware decides whether to let the request pass or limit it. to write this
  middleware ourselves in rust which gives very light processing per request";
- after the cost comparison (https://claude.ai/artifact/RwGmMP2Ff89iCxEjxApXWF): "2 layer plan
  approved".

The node's proxy is Envoy (owner's choice).

Status: **approved 2026-09-28** (the design); **the M-N0 choice, the sidecar-down rule and the two new
numbers decided by the owner 2026-09-29** (§6).

## 1. The design

**Layer 1, the edge. Before any cryptography, keyed on what is in clear.**
- **Cloud:**
  - the zone WAF rule (`terraform/waf.tf`, Free: one rule, IP, 10 s);
  - the Workers Rate Limiting bindings, keyed on IP and on the identity address: `SEALED_LIMITER` on every method at the identity door; `CEREMONY_LIMITER` on `/oauth/token`, vault PUT, `/sign` and `/auth/*`.
  - Numbers live in `wrangler.jsonc`, never in code.
  - This is the surface-bounds branch's layer; it lands there, not here.
- **Node:** Envoy in front of the node's public listener.
  - It terminates TLS and asks for the client certificate, which it forwards as XFCC.
  - The local rate-limit filter works per IP and per path; there are connection limits.
  - Numbers live in the Envoy config.

**Layer 2, the middleware. After the envelope is opened, keyed on the caller.** One Rust crate, `hdtp-limits`, owns every per-caller budget of HDTP SPEC §12:
- per contact: 1/s, burst 10;
- per identity: contacts × 1/s, capped by the measured capacity;
- guest: 10/h per root and source;
- per source: 60/h;
- the outbound budgets: to contacts, and 20/h to strangers;
- the per-integration cap of SPEC §5.7;
- a per-identity guest total checked BEFORE the open, keyed on nothing a caller can rotate;
- a cap on `pending_in` rows per identity.

The crate:
- is a pure decision function over a small state store interface: `decide(rules, key, now, state) -> Allow | Refuse{retry_after, which}`;
- has no I/O of its own;
- is compiled into the hdtp-identity Wasm package, so it runs as a separate module inside the cloud's identity object, where the envelope is opened today and where the keys already live;
- is compiled natively for the node's sidecar.

**Numbers are configuration, not code.**
- **Cloud:** one KV document, `platform-limits`, memoised in the object the way `platform-blocklist` is. It is published from the admin console and read at most every 10 s. There's a compiled default only so an unreadable document fails to a known safe set. That default is logged `limits_unreadable`; it is not a second source of truth.
- **Node:** the sidecar's config file.
- **Both:** `get_card`'s `limits` member (§12) is read from that configuration.

**What leaves the application code:**
- **Cloud:**
  - `gateway/src/identity/limits.ts` (`BUDGETS`, `bucket`, `RateLimiter`, `IDENTITY_CAPACITY_PER_SECOND`, `callLimits`);
  - the calls at `identity/surface.ts:512` and `:602`, `identity/identity.ts:293` and `:2053` (`spendOutbound`), and `integrations/rails.ts:137` (`checkRate`).
- **Node:**
  - `internal/public/limits.go` and its uses (`node/node.go`, `public/servers.go:480`, `public/sealed.go:131`);
  - the budget settings in `services/settings/settings.go`.

The storage of the counters stays where the counters are:
- the cloud's `rate_buckets` table in the identity's SQLite, now written only through the crate's state interface;
- on the node, the sidecar's own store.

The table is the middleware's state, not application logic.

## 2. Why this shape (from the comparison)

- Cloudflare can count only what's in clear, and no Cloudflare plan can count per caller. The caller is inside the sealed envelope.
- Opening an envelope measured 0.24–0.37 ms natively (0.7 ms with a P-256 chain).
  - At Workers CPU prices that's about $0.01–0.02 per million calls.
  - Opening once in the object costs nothing extra.
  - A per-IP counter is about 5,000× cheaper, so Layer 1 stops a flood before any crypto.
- Owner rule 5: leaf keys never leave a host. The cloud's middleware therefore runs in the identity object, not in the Worker or a container.

## 3. The work, in order (each item committed, gated under the gate lock, pushed before the next)

### hdtp-identity (`humandelegatedtrustprotocol/hdtp-identity`)

- **M-I1** New crate `crates/hdtp-limits`:
  - token buckets (§12's shapes), the rule set as data, and the decision function;
  - a `StateStore` trait (get/put per key with a clock seam);
  - property tests: refill, burst and the retry-after arithmetic;
  - a control that must pass: a fresh key is allowed;
  - every rule a refusal test.
- **M-I2** Contract:
  - a `limits` section in `contract/contract.json`: `limits_decide` and `limits_rules_check`, which validates a rules document;
  - `$defs` for the rules document;
  - `js/cases/limits.mjs`;
  - both ports. The Go port is needed for the node's parity.
  - This is a Wasm pin input change, so it's a re-pin.
- **M-I3** Release `0.4.0` (`make release`, `publish`, `verify-release`).

### Cloud (`batondeck/batondeck`), after feat/fair-rate-limits and feat/surface-bounds land

- **M-C1** A thin adapter in the identity object:
  - the crate's `StateStore` over `rate_buckets`, through the store, with no hand-written SQL beyond the existing statements;
  - the pre-open guest-total check at the top of `serve` for sealed calls, BEFORE `keypairs()` and HPKE;
  - the post-open decision where `rate.take` is today.
  - Every refusal keeps its current wire shape: `rate_limited`, `retry_after`, and the bucket named.
- **M-C2** `platform-limits` KV document:
  - the admin console route to publish it, validated by `limits_rules_check`;
  - the object memo (10 s);
  - the fail-safe default with its log code;
  - `get_card`'s `limits` read from it;
  - the deploy recipe publishes the initial document when it's missing.
  - Every sentence that states a number reads it from the document (rule 2 of the build rules; `no-hardcoded-counts.test.ts`). That covers the docs, `hdtp_help`, plan pages and the pricing copy in `batondeck-site`.
- **M-C3** Remove `identity/limits.ts` and every call site listed in §1: outbound budgets and the integration cap move to the crate too. `check-unwired` stays clean.
- **M-C4** Proof:
  - `make check`;
  - staging: `ship-staging`, `load-staging` (send_message and get_card, 300 and 2000 contacts), and a guest flood of fresh roots at 10× the guest total. That run must be refused BEFORE the open (the object's timing block shows no HPKE), with one control that gets through;
  - `e2e-pair`, `e2e-suite-staging`.

### Node (`humandelegatedtrustprotocol/hdtp-gateway`), after PR #15 and PR #16 land

- **M-N0 (survey, first; report back before building):** how does the sidecar get what it needs?
  - It needs the leaf private keys to open, and the caller's tier: contact, pending or guest.
  - Candidates:
    - (a) the sidecar reads a key and pin feed from the node over the local admin socket, cached, and invalidated by the change signal (N4 of the stateless plan);
    - (b) the node opens as today and asks the sidecar for a decision over the local socket with the caller's root and tier (one extra local hop, no key leaves the node process).
  - Report the security and cost of each, measured. **The owner chooses.**
- **M-N1** Envoy:
  - a `deploy/envoy/` config: TLS termination with the client certificate requested and forwarded as XFCC; the local rate limit per IP and path; connection limits; timeouts;
  - the node reads the client certificate from XFCC only when it comes from the configured proxy address;
  - a compose file that runs Envoy, the sidecar and the node;
  - a hermetic test that boots them and floods, with a control.
- **M-N2** The sidecar (`hdtp-limits` native) per the owner's choice at M-N0, with its config file. Envoy calls it through `ext_authz`, or the node calls it, per the choice.
- **M-N3** Remove `internal/public/limits.go`, its uses and the budget settings. Node SPEC §12 text now says where limits are enforced.
- **M-N4** Proof: `make check`, `analyze`, `sqlc-check`, `harness`, and `harness-nightly` with the Envoy compose.

### Protocol

- **M-P1** None required. SPEC §12's budgets are unchanged; only where they're enforced moves. If §12 says anything about enforcement placement, it's corrected in the same release as M-C3.

## 4. Build rules walk

- **Rule 1:** one implementation, the crate, behind every door: the identity object's inbound, outbound and integration paths; the node's public listener.
- **Rule 3:** every rule gets refusal tests and a control.
- **Rule 4:** layer 2 runs at the one choke point every sealed call passes (the object's `serve`; the node's decide).
- **Rule 5:** the rules document and every reader land together.
- **Rule 7:** policy refusals stay audited as today, once, in the pipeline.
- **Rule 11:** layer 1 bounds every unauthenticated input at the edge.

## 5. What this plan does not do

- Layer 1's cloud limiter changes (feat/surface-bounds carries them).
- Any change to the numbers themselves. They move from code to configuration unchanged. Changing a number is the owner's call, made in the configuration.

## 6. Amendments

**2026-09-29, the owner's decisions after the M-N0 survey** (measured under the lock: a node open is
359 µs for the small form and 518 µs for the chain form; one ask over a kept-open local socket is
5.3 µs; the decision itself 0.28 µs at any contact count):

- **M-N0 is option (b).** The node opens the envelope as it does today and asks the Rust sidecar
  for a decision over a local socket on a kept-open connection, sending the charge (root, tier,
  source, contact cap). No key leaves the node process. Envoy's `ext_authz` never sees the caller,
  so the node calls the sidecar, not Envoy. One counter is shared by every node process (N0 of the
  stateless plan).
- **When the sidecar is down, the node REFUSES.** Every sealed call answers `unavailable` until the
  sidecar is back. The node's health and status output name the sidecar's state so an operator sees
  why. The docs and the node SPEC say this in so many words.
- **The two new limits are configuration defaults:** `guest_total_calls_per_hour` = 600 per
  identity (all strangers together, charged BEFORE any cryptography) and `pending_in_cap` = 500 per
  identity. They live in the cloud's `platform-limits` document and the node sidecar's config file,
  never in code.

Also decided the same day, from the open-path benchmark: `hpke_open` and `open_result` take the
recipient's public key as an argument ("since the calling entity is the platform itself this can be
trusted"); the core never derives it from the private key on a call. Shipped in the identity core 0.4.0
(Rust) and 0.4.1 (the Go port, which 0.4.0's commit had wrongly claimed).


**2026-09-29, the owner's decision on the guest total before the open** (asked directly, relayed by
the coordinator; option (2), "let known addresses through"). Before the open nothing says who sent
a sealed call, so a total checked there alone would refuse contacts with strangers:

- **Before the open**, when the identity's guest-total bucket is empty, a sealed call is refused
  only if its source — the cloud's salted source key; the node's address — has not carried a proven
  CONTACT's call to this identity within the last hour. A source that has is let through to the
  open. Nothing is spent before the open.
- **After the open**, a guest spends the guest total (and its per-root and per-source guest buckets,
  as today); a contact spends only its contact and identity buckets. A guest from a known source is
  still refused after the open once the total is empty.
- **Known sources** are state the middleware keeps: recorded when a call opens and proves an active
  or pending contact, keyed by the salted source, with a one-hour expiry through a clock tests can
  move, and a bounded size, the oldest evicted first. The same on the node (its limits sidecar).
- **Every call that is OPENED and does not prove an active or pending contact spends the guest
  total** (the coordinator's reading of the small form, the same day): `chain_required` after the
  open, an `envelope_invalid` the open found, a guest, and a blocked root, which answers exactly as
  an unknown one (SPEC §13.3). Only a proven contact is exempt. Otherwise small forms naming
  invented fingerprints from rotating sources would cost an HPKE open each and never trip the check.
- **M-C4's flood run**: fresh roots from many sources past the total are refused BEFORE the open (the
  object's timing block shows no HPKE on them); the controls that must get through are a contact's
  call from a source that carried that contact within the hour, and a guest's call before the total
  is spent. The documented negative, and the known cost, said in the docs: a contact from a new
  source during a flood is refused with `retry_after`.

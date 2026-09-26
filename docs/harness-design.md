# Autonomous scenario harness — design

Status: **built in part.** This was written as the design for PLAN phase P14. What
exists is the registry of §4 — nineteen scenarios, each a test — the fabric, the
drivers, the VM fabric of §5 and the tiers of §6. Where a section describes more
than was built, it says so. How to add a scenario is in `docs/testing.md`.

The repo's existing tests are excellent at what they do: they assemble nodes
in-process and drive them over real TLS. What they cannot do is put a node behind
a NAT, take its network away mid-send, move the clock forward thirty days, or
open the portal in a browser. `docs/conformance.md` says so in its own words, and
six PLAN rows sit `blocked(owner-only)` for the same reason.

This harness exists to close as much of that as can honestly be closed by a
machine, and to say plainly which parts cannot be.

---

## 1. What this closes, and what it does not

The most important table in this document. A design that quietly implies six of
six owner runs become automated would be the same failure this project has spent
four review passes correcting.

### The six owner-only runs

| Run | Verdict | What substitutes for the real resource | What the substitute does **not** prove |
|---|---|---|---|
| **P10-12e** README quickstart on a clean machine | **closable** | A pristine container from the published image; README commands run verbatim; CDP completes the passkey ceremony | A genuinely fresh *host* — a different OS, a different Docker daemon version, an ARM/x86 difference |
| **P10-12i** NAT crossing, all three paths | **closable** | Two isolated bridges joined by NAT router containers (`iptables MASQUERADE`, no inbound DNAT) | Carrier-grade NAT, ISP middleboxes, real-world MTU and idle timeouts |
| **P10-12j** Own-domain VPS ingress | **partly** | Local authoritative DNS + Pebble ACME + real SNI routing between containers | Cloudflare's DNS API and tunnel-token path; Let's Encrypt rate limits and CAA; public internet routing |
| **P10-12f** Real Google Calendar booking | **partly** | Radicale (CalDAV) behind a third-party calendar MCP server we did not write | Google's OAuth consent flow, refresh-token semantics, quota and API quirks |
| **P10-12g** Tailscale Funnel, live | **not closable** | — nothing that proves anything about Funnel | Everything. A fake adapter would test our code, not Funnel |
| **P10-12h** ngrok TLS endpoint | **not closable** | — TLS endpoints require a paid plan | Everything, for the same reason |

**Four of six move. Two stay owner runs and should stay on the board as such.** Of the four,
P10-12j (T5) and P10-12f (S4) have scenarios; P10-12e (S1) has none, and for P10-12i the NAT
topology is proven (F3) but no scenario pairs or messages across it.

### The six documented coverage gaps

| Gap (`docs/conformance.md`) | Verdict | Note |
|---|---|---|
| Browser rendering — pages asserted as HTML, not screenshots | **closable** | CDP screenshots per page, both themes, plus keyboard-only traversal |
| Long-horizon behaviour — 30-day queue, 90-day invite, 24 h expiries | **closable, no code change** | See §5. Verified: a QEMU/HVF guest with `-rtc base` gets its own wall clock; `libfaketime` was measured and cannot fake a Go binary at all |
| A live ingress — pairing tested against an in-process server | **partly** | Real ACME and real SNI across containers; not a public front door |
| Live third-party reachability | **partly** | Self-hosted `frps` gives a genuine tunnel; Funnel and ngrok do not move |
| A real Google Calendar | **partly** | As above |
| A real authenticator | **partly** | CDP drives Chrome's own WebAuthn stack rather than a Go virtual authenticator — closer to real, still virtual. A physical security key stays unproven |

---

## 2. Architecture

Four layers, each replaceable without touching the others.

### Fabric — containers and networks

Everything the node talks to becomes a container, so the node is exercised
through a real socket rather than a function call.

Every image is named once, in `harness/images`: the three built here by tag, the ones pulled
from a registry by digest (`images_test.go` holds that no other file names an image).

| Service | Image / source | Why it is real |
|---|---|---|
| node | the repo's own `Dockerfile` (`images.Node`; the calendar scenario uses `Dockerfile.full` plus a pinned `caldav-mcp`, `images.Caldav`) | the shipped artifact, not a test build |
| NAT router | Alpine, `iptables` installed at start | `MASQUERADE` out, nothing in — a node behind it genuinely cannot be dialled |
| shaper | Alpine + `iproute2`, built here (`images.Shaper`) | `tc netem` for latency, loss, partition |
| bridge | `alpine/socat` | publishes a node's loopback-bound owner surface from inside its network namespace |
| dns | CoreDNS | authoritative answers for the harness zone (T5) |
| acme | Pebble | in-process in `internal/ingress/terminate_test.go`; here in a container, so ACME crosses a real network (T5) |
| frps | upstream `frp` server | **`internal/tunnel/frp.go` imports `frp/client` only** — it is the `frpc` half. `frps` is separately self-hostable and needs no account, which is what makes a *real* tunnel testable (T6) |
| caldav | Radicale + an off-the-shelf calendar MCP server | an upstream we did not write (S4) |

Designed and not built: a `hostile` server (SSRF targets, oversized bodies, slow-loris) and a
Postgres engine — every node in the harness runs its default store.

### Orchestrator

`go test` under `harness/`, **its own module** (`harness/go.mod`), driven by
`harness/cmd/harness` (`list`, `run`, `preflight`, `shaper`). This matters:
CDP means `chromedp`, a substantial dependency, and neither `make check` nor the
shipped binary should ever see it. A separate module — not merely a build tag —
keeps the root `go.mod` and the distroless image exactly as they are.

A scenario begins with `begin` (`scenario/node.go`), which registers it
(`registry.Start`) and gives it a World: a fabric named by the scenario's id and this
run's token, torn down when the test ends. `World.Node` is the one way a scenario
stands up an owned node — container, health, account, the owner's wallet certifying
it, the bridge, the passkey ceremony, the owner MCP — with its host ports from
`fabric.FreePort` (`ports_test.go` holds that no source picks one by hand).
`World.Paired` adds a contact who has redeemed an invite and been approved. What is
not an owned node is built otherwise: T5's ingress role and T6's frps are plain
fabric containers, F1–F5 build through `fabric` and `topology`, and T7 adopts the
containers the Cloudflare demo script built.

### Drivers

- **Peer driver** — reuses `internal/outbound.Client` to act as a contact's agent over mTLS.
- **Portal driver** — CDP. Registers passkeys with `WebAuthn.addVirtualAuthenticator`, renders pages as the signed-in owner, takes screenshots. (Keyboard-only traversal was designed and is not built.)
- **Admin driver** — the CLI over the admin socket, via `docker exec`.
- **Fabric driver** — `docker` CLI through `os/exec`, matching the repo's preference for few dependencies over a large SDK.

### Invariants

One is built: **the audit chain verifies** (`invariant.All`, run by F4 against T1:
each node is stopped and `audit verify` must report the chain intact). S9 makes the
same check on its own node after its probes. It is not run after every scenario.

Designed and never built, and removed from the code on 2026-09-27 rather than kept as
checks that report nothing: no session-binding growth (P12-10, unit-pinned in the node),
nothing withdrawn still callable (P12-02, P12-05), and the store passing conformance
after a scenario's writes. Invariant 4 (the relay held only ciphertext) went with
PACT 1.x.

---

## 3. Topologies

| ID | Shape | Exercises | Built |
|---|---|---|---|
| **T1** `lan` | two nodes, one bridge | direct mTLS, the happy path | `topology.LAN`, used by F4; the scenarios' own networks are this shape |
| **T2** `nat` | B behind a NAT router; A reachable | §10.1 direct-mode limits: B is reachable only through a tunnel | `topology.BehindNAT`, used by F3 only |
| **T3** `double-nat` | both behind separate NATs | a tunnel on each side is the only path | no. The builder that existed stood a relay between them and started both nodes in the relay mode PACT 1.x had and this node refuses; it went on 2026-09-19 |
| **T4** `edge` | terminating edge in front of B | `client_cert` forced off, `seal` forced required (§10.1) | no local topology; T7 runs through Cloudflare's real edge |
| **T5** `ingress` | one ingress fronting two nodes on subdomains | passthrough SNI **and** terminate, real ACME | scenario T5 |
| **T6** `tunnel` | node behind `frps` | a genuine tunnel handshake and SNI routing | scenario T6 |

No scenario runs across topologies: the T × S matrix this section once implied does not exist.

---

## 4. Scenarios

Every live scenario is registered: a `registry.Spec` literal in its own test function (id, name,
tier, needs, time budget), passed to `registry.Start`. The table below is generated from those
literals by `cd harness && go run ./cmd/harness list -doc -write` and held equal to them by
`harness/registry/registry_test.go`, so it cannot name a scenario that does not exist. The ids
are F for the fabric proving itself, S for a suite, and T for a topology that needs scaffolding
of its own (§3).

<!-- registry:begin -->
| ID | Scenario | Tier | Needs | Budget | Test |
|---|---|---|---|---|---|
| F1 | a container on an internal network cannot reach the outside | fabric | docker | 4 min | `fabric.TestLiveInternalNetworkIsGenuinelyUnreachable` |
| F2 | the NAT router admits no inbound connection, and a live run collects logs | fabric | docker | 5 min | `fabric.TestLiveNATGivesOutboundButNoInbound` |
| F3 | T2: a node behind the NAT cannot be dialled, one on the WAN can | fabric | docker, node-image | 6 min | `topology.TestLiveNATTopologyMakesBobUndialable` |
| F4 | the audit-chain invariant verifies the chains of real nodes (T1) | fabric | docker, node-image | 5 min | `invariant.TestLiveAuditChainInvariantVerifiesRealNodes` |
| F5 | a stranger sees exactly the guest tier, over real mTLS | fabric | docker, node-image | 4 min | `peer.TestLiveGuestTierSurfaceOverRealMTLS` |
| S2 | pairing and a first message, end to end, through every surface | pr | docker, node-image, chrome | 8 min | `scenario.TestPairingAndMessagingEndToEnd` |
| S4 | a contact books into a real CalDAV server through a supervised third-party MCP child | nightly | docker, caldav-image, chrome | 15 min | `scenario.TestContactBooksIntoRealCalDAV` |
| S7 | msg_id idempotency, a real partition and heal, delivery over a lossy link | nightly | docker, node-image, chrome | 12 min | `scenario.TestResilienceUnderImpairment` |
| S8 | a guest's wall clock travels a year and the unmodified node believes it | nightly | docker, kernel | 10 min | `vm.TestGuestClockTravelsAndTheNodeBelievesIt` |
| S9 | a stranger and a narrowed contact are refused, and the audit chain survives | pr | docker, node-image, chrome | 10 min | `scenario.TestAdversarialProbesAreRefused` |
| S10 | a MOVE campaign under a partition: announce answers, resume tells only the missed contact | nightly | docker, node-image, chrome | 20 min | `scenario.TestAMoveCampaignSurvivesAPartition` |
| S11 | every portal page renders in both themes with no console error | nightly | docker, node-image, chrome | 12 min | `scenario.TestEveryPortalPageRendersInBothThemes` |
| S12 | approving a contact reaches the peer: both sides active | nightly | docker, node-image, chrome | 15 min | `scenario.TestApprovingAContactReachesThePeer` |
| S13 | a rejection reaches the peer, and an unblock lets them ask again | nightly | docker, node-image, chrome | 15 min | `scenario.TestRejectingAContactReachesThePeerAndUnblockLetsThemAskAgain` |
| S14 | a conversation both ways after pairing, sealed, prompt and in the view | nightly | docker, node-image, chrome | 15 min | `scenario.TestMessagingWorksBothWaysAfterPairing` |
| S15 | the portal offers every affordance an owner needs, as drawn | nightly | docker, node-image, chrome | 12 min | `scenario.TestPortalOffersEveryAffordanceAnOwnerNeeds` |
| T5 | own-domain ingress: passthrough keeps the node's chain, terminate serves a CA certificate | nightly | docker, node-image, chrome | 15 min | `scenario.TestOwnDomainIngressServesPassthroughAndTerminate` |
| T6 | a node behind a self-hosted frps keeps its own chain and serves MCP | nightly | docker, node-image, chrome | 10 min | `scenario.TestNodeIsReachableThroughSelfHostedFrps` |
| T7 | two people over two real Cloudflare tunnels, sealed end to end | nightly | docker, chrome, cf | 20 min | `scenario.TestTwoUsersOverRealCloudflareTunnels` |
<!-- registry:end -->

**Designed and never built.** This section used to list suites that no test implements. They
were removed from the table on 2026-09-27 rather than left to read as coverage:

- **S1** first run (pristine image → wizard → passkey → dashboard; the setup token not burned on
  first use), **S3** messaging and media (inline and URL media; the SSRF guard against a
  `hostile` redirector) and **S5** the reachability matrix (T1–T6 × {direct, edge}) have no test.
- Within the suites that do exist, these cases were listed and are not exercised: S7's `kill -9`
  mid-send and the retry schedule (P12-03); S8's message expiry, queue retention, invite expiry
  and setup-token expiry (S8 proves only that the guest clock travels and the node runs at it);
  S9's session-id replay (P11-05), envelope tampering and audit tamper → `repair` refuses
  (P12-14); S11's keyboard-only traversal and a screenshot diff against a baseline (S11 compares
  each page's light and dark renders with each other).
- **S6** was relay semantics, withdrawn with PACT 1.x on 2026-09-18; its number is not reused.
  **S10** was key rotation, which 2.x does not have; the number now names the MOVE campaign.

---

## 5. Time — solved, with no code change at all

**E11 is retired. Do not add `clock_offset_seconds`.**

The owner asked for Firecracker microVMs. Firecracker cannot run on this machine:
it needs `/dev/kvm`, macOS has no KVM, and the M2 Max has no nested
virtualization (that arrived with the M3). `/dev/kvm` is absent even inside a
`--privileged` container — checked, not assumed. Firecracker remains available
only on a Linux CI host.

But the *capability* the owner was reaching for — a guest with its own kernel,
therefore its own `CLOCK_REALTIME` — is available here through a **first-level**
VM, which needs no nesting. `qemu-system-aarch64` with `-accel hvf` provides it,
and `-rtc base=<ISO datetime>` sets that guest's wall clock to any instant.

Verified on this host, guest reporting its own `date` against a host at
2026-08-25 10:44 UTC:

| Boot | Guest clock | Host after |
|---|---|---|
| control, no `-rtc` | 2026-08-25 10:43:33 | unchanged |
| `-rtc base=2026-09-24T10:00:00` (+30 d) | **2026-09-24 10:00:01** | unchanged |
| `-rtc base=2026-11-23T10:00:00` (+90 d) | **2026-11-23 10:00:00** | unchanged |
| `-rtc base=2025-01-01T00:00:00` (past) | **2025-01-01 00:00:00** | unchanged |

The guest clock **advances** — 10:00:01 then 10:00:03 two seconds later — rather
than freezing. QEMU runs unprivileged and never calls `settimeofday(2)`, so the
host clock is untouched; two guests with different bases run concurrently, each
keeping its own time.

**"Zero source changes" is exact, not approximate.** Verified four ways: no
production code anywhere sets a non-nil `Now`; `node.Options.Now` is never set
outside tests; every `now()` helper nil-checks and falls back to `time.Now()`;
and `NewLimiter` nil-checks explicitly. A VM clock therefore reaches every seam
E11 was written about — without putting a time-travel switch on token expiry,
invite expiry and envelope freshness.

### Why the container-level alternatives all fail

`libfaketime` was ruled out on the argument that the image is `CGO_ENABLED=0` on
distroless-static, so there is no dynamic loader to preload. That argument is
sound but incomplete, and the fuller reason is worth recording because a
well-regarded tutorial recommends exactly this technique. **Measured**, in one
Debian container with `libfaketime` preloaded and `FAKETIME="2022-05-01 11:53:20"`:

| Measured with | Result |
|---|---|
| `date` (C, uses libc) | 2022-05-01 11:53:20 — faked |
| a Go binary calling `time.Now()` | 2026-08-25 10:02:06 — **untouched** |

Go reads the clock through the vDSO and bypasses libc entirely; `libfaketime`
hooks libc symbols. It cannot fake a Go program at all, on any base image. The
tutorial's demo appears to work only because it measures with `date`.

The other container-level options fail for their own reasons: an NTP client needs
`privileged` plus host networking and then sets the **shared** clock; `SYS_TIME`
plus `date -s` writes the host clock; mounting `/etc/localtime` changes the
timezone, not the clock; and Linux time namespaces deliberately do not virtualize
`CLOCK_REALTIME`.

### What a clock jump does and does not break

Verified by reading the code:

- **Pinned contacts are time-independent.** `internal/outbound/client.go` returns
  `nil` on an SPKI fingerprint match *before* reaching `leaf.Verify`, and sets
  `InsecureSkipVerify: true`. Two nodes 30 days apart still complete mTLS.
- **Identity certificates carry 10-year validity** (`NotAfter: now.AddDate(10,0,0)`),
  so a 90-day jump is far inside the window.
- **The audit chain survives a jumped timestamp** — ordering and verification are
  by `seq` and `prev_hash`; nothing asserts timestamp monotonicity.
- **CAVEAT — the WebPKI path IS time-dependent.** The fallback branch in the same
  function calls `leaf.Verify`, which checks `NotBefore`/`NotAfter` against the
  current clock. A time-travelled node talking to anything trusted by WebPKI
  rather than by pin — an ACME-issued ingress certificate — can fail on cert
  validity. Today this is latent, because Pebble runs
  in-process inside the test binaries rather than as a separate machine. In a VM
  fabric with a containerised ACME it becomes live, and S8 scenarios must either
  stay on pinned peers or issue certs whose validity spans the jump.
- **TRADE-OFF — schedulers are monotonic.** Retention, retry and health sweeps all
  use `time.NewTicker`, which a wall-clock jump cannot accelerate. Prefer
  `-rtc base` **at boot** over a live `date -s`: `internal/cli/retention.go` also
  calls `sweep()` once at startup, so a node booted at T+30d applies retention
  immediately, whereas a node jumped mid-run waits up to an hour. Model long
  horizons as "restart this node with a new base" — which is a realistic node
  restart anyway.

### Built (P14-09)

`harness/vm` implements this. The guest runs the ordinary shipped binary — no
build tag, no flag, nothing about time — and the same image booted twice reports
2026-08-25 with no `-rtc` and **2027-06-01** with `-rtc base=2027-06-01T12:00:00`,
creating an account and verifying its audit chain at both. The host clock is
untouched. Boot to finished is about six seconds.

### Shape of the change

S8 runs as its own **QEMU/HVF fabric**, not as a variant of an existing cell; the
container topologies are plain `docker` networks. This is a hybrid fabric,
deliberately: the binary is `CGO_ENABLED=0` static, so the guest needs no Docker
inside it — just a minimal arm64 rootfs, which `harness/vm/rootfs.go` builds in a
throwaway Alpine container. S8 is nightly-tier only, and nightly promises it only
when `PACT_HARNESS_KERNEL` names a kernel (`make harness-kernel`). On 2026-09-27 the
whole scenario — cross-building the node, building the rootfs, booting twice — took
13.9 s.

## 5a. The harness plays the wallet

A PACT 2.x account is nobody until a wallet has signed it a leaf: the identity is the person's
root, which no host holds, and `account create` makes an account with no certificate to present.
So `harness/wallet` holds a root per person and does what an owner does with the `pact` CLI —
`account csr`, issue under the root, `account install-leaf` — and hands a scenario the pin a
caller holds: the root, the leaf, the address in it. Three things follow, each learned by
running it:

- **A node's public URL is a name, never a loopback address.** No wallet issues a leaf for one
  (PACT §14.2 rule 5), and a chain is validated against the address dialled. A node published on
  `localhost` is therefore named (`alice.harness.example:<port>`), and the harness agent resolves
  that name to the published port (`peer.Target.Dial`), which is DNS's job for a real caller.
- **A scenario that touches the portal is an OWNER.** The portal requires a session on every
  bind (SPEC §8.3), so the browser that runs the passkey ceremony hands its cookies to plain
  HTTP (`scenario.OwnerSession`), and a setting is posted as that owner.
- **An affordance is asserted on the page a browser DRAWS.** The portal is one page over a JSON
  API; the document behind every path is the same empty shell. `portal.Session.Rendered` reports
  the words, links and controls of the settled view, signed in (`OwnerSession.Browser`).

**Status, 2026-09-19 — `PACT_HARNESS_LIVE=1 go test ./...` against a fresh `make harness-image`
and `make harness-image-caldav`: 15 live scenarios pass, 2 skip** (Cloudflare tunnels need a real
domain, `PACT_CF_DOMAIN`; the VM clock test needs `PACT_HARNESS_KERNEL`). The same command that
morning: **0 pass.** Every scenario still created an account and called it — the whole ceremony
while a node's key was its identity — so every first dial ended `tls: internal error`; five more
scraped server-rendered HTML the portal stopped producing, or posted forms as nobody. None of it
showed, because a live scenario is skipped unless `PACT_HARNESS_LIVE` is set and the pre-push
hook does not set it. **The hermetic tier being green says the harness COMPILES. It says nothing
about whether a scenario can run**, and only a live run does.

**Status, 2026-09-27 — `make harness-nightly` with `PACT_HARNESS_KERNEL` set: 18 scenarios
PASS, T7 not promised** (no `PACT_CF_DOMAIN`), and the tier says so rather than passing it
silently (§6).

## 6. Run tiers

A tier is a set of registered scenarios (§4), chosen by the `Tier` in each spec —
tiers nest, fabric ⊂ pr ⊂ nightly — never by a regular expression over test names.
`go run ./cmd/harness run -tier <t>` prints what the tier PROMISES (every scenario
whose needs it provides), runs `go test -v -count=1` on exactly those tests with a
`-timeout` summed from their specs, and fails if a promised scenario did not PASS —
a skip included. A scenario it does not promise is printed with what would provide
it. `docs/testing.md` has the needs, the result files and how to add a scenario.

| Tier | Runs | Promises (needs it provides) | Measured 2026-09-27 | How |
|---|---|---|---|---|
| **Hermetic** | every harness package's unit tests, the registry, image and port guards, `go vet` | — (runs no scenario) | `make harness` | `pre-push` hook, automatic |
| **Fabric** | F1–F5 | docker, node image | 5/5 PASS; the five took 10.4 s | `make harness-live` |
| **PR** | fabric + S2, S9 | + chrome | 7/7 PASS; the seven took 21.3 s | `PACT_PREPUSH_LIVE=1 git push`, or `make harness-pr` |
| **Nightly** | every scenario | + caldav image; kernel only with `PACT_HARNESS_KERNEL`, cf only with `PACT_CF_DOMAIN` | 18 PASS, T7 not promised; the scenario package took 104.8 s | `PACT_PREPUSH_LIVE=full git push`, or `make harness-nightly` |

The measured times are the scenarios' own (the sum of the verdicts' durations, or the
package's time), from one run on one machine with every image already built. Building the
images is not counted.

**None of this runs in GitHub CI, and that is deliberate.** The live tiers drive
real containers and a real Chrome over CDP; a runner has neither Chrome nor a
reason to build the product image, so running them there reported the runner's
missing browser (`chrome failed to start`) rather than anything about the
product. The machine that can run this is a developer's, so that is where it
runs — `make hooks` installs the `pre-push` hook that does it. CI keeps what it
is genuinely good at: `make check` on both storage engines, the analyzers, and
the fuzzers.

**What the PR tier does not run, stated so it is not mistaken for full coverage:**
everything the nightly tier adds — S4, S7, S8, S10–S15, T5–T7. A green PR run means
"the fabric, pairing and the adversarial probes hold", not "the system is verified".

---

## 7. On failure

A tier run leaves `<id>.json` per scenario and a `summary.json` in its results
directory (printed at the start of the run). With `PACT_HARNESS_ARTIFACTS` set, each
scenario's World writes every container's log there at teardown, and S11 saves its
screenshots there. Nothing else is collected: the store file, the audit export,
`tc`/`iptables` state, the CDP console transcript and a `pcap` were designed and are
not built — S11 asserts on console errors and prints them, but does not save them.

---

## 8. Risks

- **Flakiness.** Real networking is not deterministic. Mitigation: waits poll to a
  deadline (a node's health, the published owner surface, a log line, a zone) rather
  than sleeping a guessed interval; the loops that do sleep between polls are bounded
  by a deadline. Every scenario states its own timeout in its spec. There is no retry:
  a failed scenario fails its tier.
- **Collisions.** Two scenarios, or two runs, fighting over a port or a name. Mitigation:
  host ports come from `fabric.FreePort`, and every name carries the scenario's id and
  a per-run token (`fabric.PrefixFor`).
- **Image drift.** Mitigation: upstream images are pinned by digest (`harness/images`);
  the node image is rebuilt by each tier's Makefile target, from Docker's layer cache.
- **Docker-in-CI privileges.** `iptables` and `tc` need `NET_ADMIN`. Mitigation:
  confine it to the `nat-*` and `shaper` containers; the node containers stay
  unprivileged, as they ship.
- **Scope creep into a second product.** Mitigation: the harness asserts only
  what SPEC states. A scenario that cannot cite a section does not belong.

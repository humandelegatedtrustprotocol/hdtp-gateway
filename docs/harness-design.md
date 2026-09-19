# Autonomous scenario harness — design

Status: **design, not built.** Nothing in this document exists yet. It is written
to be executed as PLAN phase P14, and to be argued with first.

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

**Four of six move. Two stay owner runs and should stay on the board as such.**

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

| Service | Image / source | Why it is real |
|---|---|---|
| `node-*` | the repo's own `Dockerfile` | the shipped artifact, not a test build |
| `nat-*` | `alpine` + `iptables` | `MASQUERADE` out, nothing in — a node behind it genuinely cannot be dialled |
| `shaper` | `alpine` + `iproute2` | `tc netem` for latency, loss, partition |
| `dns` | small Go binary on `miekg/dns` (**already a dependency**) | authoritative answers for the harness zone |
| `acme` | Pebble | **already a dependency** — today it runs *in-process* in `internal/ingress/terminate_test.go`; here it moves to a container so ACME crosses a real network |
| `frps` | upstream `frp` server | **`internal/tunnel/frp.go` imports `frp/client` only** — it is the `frpc` half. `frps` is separately self-hostable and needs no account, which is what makes a *real* tunnel testable |
| `caldav` | Radicale + an off-the-shelf calendar MCP server | an upstream we did not write |
| `hostile` | small Go binary | SSRF targets: redirects into private ranges, oversized bodies, slow-loris |
| `postgres` | `postgres:16-alpine` | the engine CI already skips without a DSN |

### Orchestrator

A Go program under `harness/`, **its own module** (`harness/go.mod`). This matters:
CDP means `chromedp`, a substantial dependency, and neither `make check` nor the
shipped binary should ever see it. A separate module — not merely a build tag —
keeps the root `go.mod` and the distroless image exactly as they are.

### Drivers

- **Peer driver** — reuses `internal/outbound.Client` to act as a contact's agent over mTLS.
- **Portal driver** — CDP. Registers passkeys with `WebAuthn.addVirtualAuthenticator`, takes screenshots, traverses by keyboard.
- **Admin driver** — the CLI over the admin socket, via `docker exec`.
- **Fabric driver** — `docker` CLI through `os/exec`, matching the repo's preference for few dependencies over a large SDK.

### Invariants — asserted after *every* scenario

Not a suite; a suite-wide postcondition. Each of these is a regression this
project has already had, which is why they are cross-cutting rather than local:

1. **The audit chain verifies**, and its anchor matches (§11.6).
2. **No session-binding growth** — the map is proportional to live sessions (P12-10).
3. **Nothing withdrawn is still callable** — every tool absent from `tools/list` is refused on call (P12-02, P12-05).
4. *(withdrawn with PACT 1.x, 2026-09-18: there is no relay role, so there is no relay to hold ciphertext)*
5. **The store passes conformance** after the scenario's writes, on both engines.

---

## 3. Topologies

| ID | Shape | Exercises |
|---|---|---|
| **T1** `lan` | two nodes, one bridge | direct mTLS, the happy path |
| **T2** `nat` | B behind a NAT router; A reachable | §10.1 direct-mode limits: B is reachable only through a tunnel |
| **T3** `double-nat` | both behind separate NATs | *(not built)* a tunnel on each side is the only path. The builder that existed stood a RELAY between them and started both nodes `relay-assisted`, a mode PACT 1.x had and this node refuses; it went on 2026-09-19 |
| **T4** `edge` | terminating edge in front of B | `client_cert` forced off, `seal` forced required (§10.1) |
| **T5** `ingress` | one ingress fronting two nodes on subdomains | passthrough SNI **and** terminate, real ACME |
| **T6** `tunnel` | node behind `frps` | a genuine tunnel handshake and SNI routing |

---

## 4. Scenario suites

| ID | Suite | Notable cases |
|---|---|---|
| **S1** | First run | pristine image → wizard → passkey → dashboard; the setup token is **not** burned on first use (P12-07) |
| **S2** | Pairing | invite → QR → redeem → approve → first message, per topology |
| **S3** | Messaging & media | text, inline media, URL media; SSRF guard against `hostile` redirecting into a private range |
| **S4** | Calendar | availability filtering (≤5 slots, never raw free/busy) and `book_slot` against real CalDAV |
| **S5** | Reachability matrix | T1–T6 × {direct, edge}; asserts the §10.1 mode rules refuse what they must |
| **S6** | *(withdrawn)* | Relay semantics. The relay role went with PACT 1.x on 2026-09-18 and `relay_live_test.go` with it; the number is kept so the others do not move |
| **S7** | Resilience | `tc netem` partition/loss/latency; `kill -9` mid-send; retry schedule holds (P12-03); `msg_id` idempotency across every retry |
| **S8** | Time | 24 h message expiry → failed; 30-day queue retention; 90-day invite expiry; 24 h setup token. **Requires §5.** |
| **S9** | Adversarial | session-id replay under a second identity (P11-05); tier escalation attempts; envelope tampering; audit tamper → `repair` refuses (P12-14) |
| **S10** | *(withdrawn)* | Key rotation. There is none: the identity is a root the node does not hold. Its successor would be the MOVE campaign under partition — `account announce` resuming an interrupted `update_contact` walk — which no scenario covers yet |
| **S11** | Portal (CDP) | every page, both themes, screenshot diff; keyboard-only traversal; no console errors |

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

S8 runs as its own **QEMU/HVF topology**, not as a variant of an existing cell.
The other five topologies stay on Compose. This is a hybrid fabric, deliberately:
the binary is `CGO_ENABLED=0` static, so the guest needs no Docker inside it —
just a minimal arm64 rootfs — and S8 is nightly-tier only. What remains to build
is that rootfs; nothing else about the harness changes.

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

## 6. Run tiers

Six topologies × eleven suites is roughly sixty cells. Running all of them on
every push would be slow enough that people would stop reading the result.

| Tier | Cells | Wall clock (est.) | When | How |
|---|---|---|---|---|
| **Hermetic** | fabric, topology, preflight, invariants against a recorder | ~5 s | every push | `pre-push` hook, automatic |
| **Fast** | T1, T2 × S1, S2, S3, S9 + all invariants | ~8 min | on demand | `PACT_PREPUSH_LIVE=1 git push`, or `make harness-pr` |
| **Full** | the full matrix, including S4, S7, S8, S11 | ~45 min | on demand | `PACT_PREPUSH_LIVE=full git push`, or `make harness-nightly` |
| **Release** | full + both store engines + `-race` throughout | ~70 min | before a tag | by hand |

**None of this runs in GitHub CI, and that is deliberate.** The live tiers drive
real containers and a real Chrome over CDP; a runner has neither Chrome nor a
reason to build the product image, so running them there reported the runner's
missing browser (`chrome failed to start`) rather than anything about the
product. The machine that can run this is a developer's, so that is where it
runs — `make hooks` installs the `pre-push` hook that does it. CI keeps what it
is genuinely good at: `make check` on both storage engines, the analyzers, and
the fuzzers.

**What the fast tier does not run, stated so it is not mistaken for full coverage:**
T3–T6 entirely, resilience (S7), time travel (S8) and portal
screenshots (S11). A green PR run means "the common paths and the adversarial
probes hold", not "the system is verified".

---

## 7. On failure

A failed scenario is worth nothing without the evidence. Each run collects, per
container: logs, the store file, the audit export, `tc`/`iptables` state, and —
for portal scenarios — the screenshot and the CDP console transcript. A `pcap`
from the shaper is captured for S5 and S7, where the question is usually "did the
packet leave at all".

---

## 8. Risks

- **Flakiness.** Real networking is not deterministic. Mitigation: no `sleep`
  anywhere — poll to a deadline; every scenario states its own timeout; a retry
  budget of one, with the retry recorded in the report rather than hidden.
- **Image build cost.** The node image is rebuilt per run. Mitigation: layer
  cache keyed on `go.sum`, and one image shared across all cells in a run.
- **Docker-in-CI privileges.** `iptables` and `tc` need `NET_ADMIN`. Mitigation:
  confine it to the `nat-*` and `shaper` containers; the node containers stay
  unprivileged, as they ship.
- **Scope creep into a second product.** Mitigation: the harness asserts only
  what SPEC states. A scenario that cannot cite a section does not belong.

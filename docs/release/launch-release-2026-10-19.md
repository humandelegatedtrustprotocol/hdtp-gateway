# Launch release — hdtp-gateway v0.3.0 and hdtp-gateway-agent 0.1.0 — plan

Status: **draft for the owner** (2026-10-19). Owner's order: "we need to get all release ready". Standing
rulings this plan applies: the ghcr image is the install path (2026-10-18); a public demo node answered by
the open-source agent; BatonDeck is not part of this launch; the demo agent first, then the video. Zones: a
release is Z3, a migration Z2, a host tool Z4, a key or token Z8, infrastructure Z1, package visibility Z5
(the owner runs it).

Verified state, read 2026-10-19: node `origin/main` is at `0ae57ca` (the local checkout is behind at
`4906e99`; everything below was read from `origin/main`). W0–W3 landed in #209; of W4, the SPEC prose and
the two door-divergence tests are done, and four pieces are not: the parity test that reads the sibling
`batondeck` registry (today `events_test.go:33` carries the cloud's names in a comment, and
`internal/services/webhooks/README.md` says so), the README how-to, the harness scenario, and the CHANGELOG
entry (`[Unreleased]` has no webhooks entry at all). Mem0 holds an owner ruling of 2026-10-18 that the ghcr
image is the launch's install path, which makes SPEC §1/§12.3/§12.5 ("no image is published"), the
README/quickstart/deploy.md/cloud-init Rust-and-cargo steps and hdtp.dev's quickstart block false the
moment the image exists. The agent has no tag, `package.json` is `0.0.0`/`private`, no Dockerfile or
compose, and the README says "Work in progress: the full README follows."

## What exists (read 2026-10-19 from `origin/main` of each repository)

| Surface | Observed |
|---|---|
| Node main | `0ae57ca`: #209 (webhooks W0–W3), #228 (pre-release), #233 (#232) merged. Open: #236 (`feat/owner-asks` at `014f0d8`, 74 files, mergeable). |
| W4 on main | Done: SPEC §7.8 (dispatcher, third consumer), §8.2 (Webhooks page), §8.5 ("pushes nothing" rewritten), §11 tables, §12.5; `TestNoOwnerMCPToolTouchesAWebhook`, `TestNoCommandTouchesAWebhook`; `webhooks/README.md` names every divergence. **Not done:** the parity test reading `batondeck/gateway/src/events/registry.ts` (the names are a comment at `events_test.go:33`; the README says "Not held here … (W4)"); the envelope/header grammar test against the cloud; README how-to; a harness scenario (`git grep -il webhook harness/` is empty); the CHANGELOG entry. |
| CHANGELOG | `[Unreleased]`: hook/sibling changes, #208, #221, #204, #210, #207, #232, #219, #213, the `web/tools` removal. No entry for webhooks. #236 adds 18 lines for asks. |
| Release mechanics | `RELEASING.md`: annotated tag → fresh clone → `make dist VERSION=` (tree and VCS-stamp checks, `scripts/release-check.sh`) → `make sbom` → `gh release create` with the 8 binaries, `SHA256SUMS`, `sbom.cdx.json`, `THIRD_PARTY_NOTICES`. No image target; `Makefile` builds `hdtp-gateway:harness` only. `Dockerfile` (distroless, `ARG VERSION`, no OCI labels). No GitHub workflows. `main.version` is stamped by `-ldflags`; nothing else in code carries the version. |
| SPEC header | `Version 0.2.2-draft · 2026-10-03` at v0.1.5, v0.2.0 and main: the header has not tracked releases. |
| Prose that becomes false with a published image | SPEC.md:50 ("none is published"), §12.3 ("No image is published … built locally"), §12.5 ("carry binaries, not images"); README.md:82–90 (Rust/cargo, `make limitd-vendor`); docs/quickstart.md:31–75; docs/deploy.md:37–38, 275–277 and `deploy/cloud-init.yaml` (vendors crates and builds on the VM; held to compose.yaml by `make deploy-check`); hdtp-gateway-site `public/index.html:294–303`. |
| Node README / hdtp.dev on the agent and webhooks | Neither mentions either (grep). Nothing false today; the how-to is W4's. |
| Agent main | `6343974`: #1, #12, #14, #16, #18, #19, #21, #23, #27, #38 merged. Open: #36 (`feat/reply-ask-notify` at `3a62d1b`, fixture `test/owner-mcp-tools.json` captured from #236's `014f0d8`). A5 (`feat/studio-observability`) is local, not on the remote. |
| Agent release surface | `package.json` `0.0.0`, `private: true`, Apache-2.0 LICENSE present, no CHANGELOG, no Dockerfile, no compose, `Makefile` `check: typecheck build test`, hooks in `githooks/`. README: WIP; claims "the first hdtp-gateway release after v0.2.0 … (v0.3.0 is planned)". `docs/a2-observed.md`: A2 observed natively (two binary nodes, `make dev`). `docs/advisories.md`: two unpatched upstream advisories, each shown not to apply. |
| Demo-node primitives | Invites: `max_uses` (0 = unlimited, `store/params.go:178`), `auto_accept`, `preset`, `ExpiresAt` (rule read by the builder); `deploy/` has four VM templates on one `cloud-init.yaml`, none yet run on a provider; `deploy/limitd/limits.json`: guest 10/h per identity, 60/h per source, 600/h total, contact 1/s burst 10, `pending_in_cap` 500. Agent: `HDTP_AGENT_ANSWER=all`, `HDTP_AGENT_REPLIES_PER_HOUR` per contact (10), no global cap; bind is `127.0.0.1` hard-coded (`src/mastra/index.ts:22`). |

## Triage

Classes: **R** = blocks release (v0.3.0 or agent 0.1.0), **D** = blocks the demo node (A4), **A** = after
release. In flight and not re-planned: node #236, agent #36, agent A5, batondeck #351; agent #34 closes
with #36.

### Node

| # | Class | Reason |
|---|---|---|
| 193 | A | Lint gap; the one row it misses (`add_contact` ok row without an account) is audit scope, not a user path. |
| 194 | R (prose) | A documented command fails; one line in `docs/crypto-review-brief.md`, rides the W4 prose PR (rule 2). |
| 196 | D | Under launch limits the demo node refuses handshakes; a visitor's tools/list then reads "unreachable" instead of the refusal with its wait. First-contact path. |
| 197 | A | Latent; no argument struct hits it today (the review checked). |
| 198 | A | Cloud parity on two held states; the node still answers, after a dial. |
| 199 | A | Two answers for one stranger; needs a SPEC §5.4/§5.8 decision; leaks only which tools are guest tools. |
| 200 | A | Race between two concurrent decisions of one root; narrow. |
| 201 | A | Expiry clock of a moved pending row; cloud comparison first. |
| 202 | A | Audit-order defect needing a design decision; not a user path. |
| 211 | A | Two accounts on one node reaching each other is not a documented path; the demo node has one account. |
| 212 | A | Tooling. The release push uses the keepalive from the issue (step N-R2 below). |
| 214 | A | Dead shared symbol; cloud-shared file. |
| 215 | A | Upstream report. |
| 216 | A | Audit provenance (rule 7), not security. `services/auditsink/auditsink.go:78`. |
| 217 | A | Shutdown waits bounded by driver timeouts, not unbounded growth. |
| 218 | R (Z2) | Migration `0006_webhooks` is in no release: the index goes into it now for free; after v0.3.0 it costs a migration forever. Measure first as the issue says. Dev nodes that already applied 0006 stay as they are (none is released). Owner approves at the Z2 prompt. |
| 220 | D | Reproduce first. The demo node restarts (deploys, crashes); an agent-mode exposure that silently drops to tools:0 breaks the demo's capability path until the owner re-saves. If it reproduces on the documented path (expose, reconnect, restart), it moves to R. |
| 222 | A | `GET /api/integrations` sends `store.Integration` rows; the row holds no credential (`store.go:337`). Portal API, not a public tool. Rule 10 hygiene. |
| 223 | R | An owner-MCP shape (`hdtp://thread/<id>`) answers raw `store.Message` rows (`Seq`, `AccountID`, `Attempts`, `NextAttemptAt`, `ExpiresAt`) and lacks `message_id`; a shape change is cheaper before v0.3.0. |
| 224 | R | `FetchMedia` answers `internal` for an unknown account (`send.go:554`); the same wrong answer #207 fixed for send. Rule 3. |
| 225 | R | Two shapes for one operation on two doors; cheaper before v0.3.0 (the lead's own example). |
| 226 | R | Reproduce first. Settings on the binary (the "Without Docker" quickstart path) failed to apply with a generic sentence. `SetSeal` returns `node: unknown account` for an account not served (one awaiting its certificate); the apply then fails the whole knob with no code. |
| 227 | A | Harness bridge only. |
| 229 | A | The fix is additive (give the portal `message_id` beside `id`); it breaks nothing later. |
| 230 | A | Window narrowed by #228; clock-per-claim later. |
| 231 | A | The owner's open page shows "sending" until reload; no wire effect. |
| 234 | R | Wire shape of a public tool (`ThreadID`, `Status`), cheaper before v0.3.0; the agent reads `ThreadID` (`src/hdtp/node.ts:133`) so the agent changes in the same release. |
| 235 | A | Behaviour, not shape; the cloud does the same; needs a SPEC §7 decision for both. |
| 237 | A | A missing scenario for #236's feature; an issue with evidence, as the review rules want. |
| 238 | A | Same-second tie in the portal composer. |

### Agent

| # | Class | Reason |
|---|---|---|
| 4 | A | Library stderr text; the operator's own log. Rule 10 hygiene. |
| 5 | A | A3's README says Studio's chat is not the contacts' framing (rule 2); the wrapper later. |
| 8 | A | Confirm against the node's `list_pending`; hold with a test. |
| 9 | D | Measure with the demo model. If a draft misses the node's 30 s hold, the demo exposes no agent-answered capability (decision 7). |
| 20 | A | Test speed. |
| 24 | A | A 1-in-10 teardown flake; the 0.1.0 gate run is repeated on a flake and the run is reported as such (step A-R2). |
| 25 | A | A3's README says a capped thread is marked read (rule 2). |
| 26 | A | Log repetition; the demo node (`ANSWER=all`) has no untrusted threads. |
| 28 | A | Budget race on two threads of one contact; the thread is left for the owner, not lost. |
| 29 | A | A3's README names the unwritable case (rule 2). |
| 30 | A | Not hit with `ANSWER=all` (no untrusted threads). |
| 31 | D | The agent beside the demo node runs in its compose project (decision 6); the node cannot reach a loopback bind. Needs the bind decision and Studio's guard for it. |
| 32 | A | Inert: no browser agent exists, and Studio's port is not published on the demo host. |
| 33 | A | `--https` Studio only. |
| 34 | — | Closes with #36. |
| 35 | A | A wrong code in the agent's own log; #236's catalog passes (#36 captured all twelve tools). |
| 37 | A | `make check` builds before it tests (`Makefile`); only a bare `vitest run` fails. |
| 39 | R (prose) / A (code) | The README sentence #36 adds is unconditional and the code is not; A3 makes the sentence true. The restart redraft is A. |
| 40 | A | One extra model call per replayed message after a restart, inside the per-contact budget. |

## Items

Each item: its own worktree, `git add` by path, gates under `lockf .claude/locks/gate-node.lock` (node) or
`gate-other.lock`, mutation-checked tests shown red first, one PR, its body naming the surfaces it adds and
which of Building rules 1, 3, 4, 5, 7 did not apply.

### Node, before v0.3.0

**N-W4 — "Webhooks W4: parity, prose, harness, index"** (lane: `builder`, node). After #236 merges (its
`ask.answered`/`ask.expired` join the subscribable names).
- Fixes: W4's four open pieces, #218, #194.
- Parity test reading sibling `batondeck/gateway/src/events/registry.ts` (`testid.SiblingDir`, as the
  existing guards do): the node's `Subscribable()` is a subset of the cloud's `emitted: true` names, with
  the divergence list in code (the cloud's `contact.*`, `booking.*`, `integration.attention`, `identity.*`
  not emitted; `ask.*` node-only). A second test holds the envelope keys and the signature grammar to the
  cloud's `sign.ts` constants read from the sibling. `webhooks/README.md`'s "Not held here" sentence goes.
- README how-to "Wake your agent with a webhook": the portal steps, the headers, a verifier in JS and Go
  taken from `verify_test.go`, a link to `hdtp-gateway-agent`. Grep every umbrella repository for prose
  saying the node pushes nothing (`batondeck` docs included) and fix what the grep finds in the same PR or
  file it.
- Harness: one hermetic scenario in `harness/scenario/`: a contact messages the node, an `httptest`
  receiver registered through the portal's route gets a signed `message.received` and verifies it.
- #218: measure the hourly delete at 1M rows with and without the index, add
  `CREATE INDEX webhook_deliveries_created ON webhook_deliveries(created_at)` to
  `migrations/{sqlite,postgres}/0006_webhooks.sql` (Z2 prompt), `make sqlc-check`.
- CHANGELOG `[Unreleased]` → Added: the webhooks (what is posted, the one attempt, the pause, the portal
  page, the headers, the divergences from the cloud), the index.
- Acceptance: Building 1 (one list, held to the cloud by a test), 2 (every README sentence from
  `webhooks/README.md`'s measured behaviour), 5 (every offered name has an emitter — the existing test),
  6 n/a. Observed: `make check`, `make analyze`, `make sqlc-check`, `make harness` green; the parity test
  red when one name is removed from the divergence list.

**N-SHAPES — "Owner doors: one shape per operation before v0.3.0"** (lane: `builder`, node). Parallel
with N-W4 (no shared files but CHANGELOG; rebase, never force).
- Fixes: #234, #225, #223, #224.
- #234: `send_to_contact` answers `{thread_id, status}` projected explicitly; the tool description names
  `thread_id`; a test holds the keys; the CHANGELOG names the break.
- #225: one invite shape on the portal's `/api/invites` and the owner MCP's `create_invite`/`list_invites`,
  compared with the cloud's (`createInvite: id, url, expires_at`); or a named divergence held by a test.
- #223: `hdtp://thread/<id>` answers `read_thread`'s projection (with `message_id`), one function under
  both doors; a test holds the two equal.
- #224: `FetchMedia` of an unknown account is `refusal.NotFound`, with the five refusals of rule 3 on the
  door that calls it.
- Acceptance: Building 1, 3, 10. Observed: the owner MCP's `tools/list` and one `send_to_contact` call
  from a real client (the agent's `test/wire.ts` fake is not the observation); the agent's fixture
  recapture is A-SHAPES.

**N-SETTINGS — "#226: Settings on a host node"** (lane: `builder`, node). Reproduce on a binary node with
one account awaiting its certificate; fix the side that is wrong (an account not served is skipped with
its own row, or the knob answers a code), with the test red first. Acceptance: rule 3, 7 (one truthful row
per save); observed on a real binary node's Settings page: save, reload, the value held.

**N-IMAGE — "The published image is the install path"** (lane: `builder`, node; prose to `cheap` after
the builder's probe). After N-W4 (both touch README).
- Feasibility probe first (rule 4): `docker buildx build --platform linux/amd64,linux/arm64` of the
  `Dockerfile` on the owner's Mac with the vendored crates context; measure the Rust stage under
  emulation; load one platform and run `hdtp-gateway version`. The probe's time goes in this file. If
  emulation is unworkable, the Dockerfile cross-compiles the sidecar (a second probe) before anything else
  is built.
- `Makefile`: `image` target — `buildx`, two platforms, `--build-arg VERSION`, tags
  `ghcr.io/humandelegatedtrustprotocol/hdtp-gateway:<version>` and `latest` (decision 1), `--push` only
  with `PUSH=1`; refuses outside a clean tag tree as `dist` does. `Dockerfile`: OCI labels (`source`,
  `version`, `licenses`, `description`); the `source` label is what links the package to the repository.
- `compose.yaml`: `image:` named by `${HDTP_IMAGE:-ghcr.io/…:<version>}`, the from-source `build:` moved
  to `compose.build.yaml` (decision 2); `make deploy-check`, `cloud-init.yaml` and `docs/deploy.md` follow
  (the VM pulls; the vendoring and build steps go). The harness keeps `make harness-image`.
- Prose (rule 2): README quickstart (no Rust, one command), docs/quickstart.md, SPEC.md:50, §12.3, §12.5,
  RELEASING.md (the image step; what the image is held to: built by the maintainer from the fresh clone
  of the tag, `-X main.version`, its manifest digest in the release notes, not byte-reproducible because
  the base images are named by tag — say so). CHANGELOG `[Unreleased]` → Added.
- Acceptance: rule 2 on every sentence above (the measured quickstart time is written only after N-R6).
  Observed before merge: `docker compose config` of the new file;
  `docker compose -f compose.yaml -f compose.build.yaml up` builds and serves as before;
  `make deploy-check` green.

**N-RELEASE — "v0.3.0"** (lane: `builder`, node; the session runs the release, the owner approves each
zone). Steps N-R1–N-R7 below.

### Agent, before 0.1.0

**A-SHAPES — "Read the node's thread_id"** (lane: `builder`, agent). After #36 and N-SHAPES merge.
`src/hdtp/node.ts` reads `thread_id`/`status`; `test/wire.ts`'s fake answers the new shape (rule 5, both
ends); `test/owner-mcp-tools.json` recaptured from N-SHAPES's merge sha (the `send_to_contact`
description changed). Observed: one reply against a node built from that sha.

**A-README — A3** (lane: `cheap`, agent, after A5 merges per decision 5). The README from
`docs/a2-observed.md` and the code: what it answers and leaves (#36's four turns), the persona, models,
Studio, the token and the webhook in the portal, observability (A5), "needs hdtp-gateway v0.3.0 or
later", the Studio framing note (#5), the capped thread is marked read (#25), the unwritable data dir
(#29), #39's sentence made conditional, the run commands observed once (`npm run build` + `npm start`, or
`make dev` only). "Work in progress" goes. `package.json` `version: 0.1.0` (`private` stays: no npm
publish was ordered). CHANGELOG.md starting at 0.1.0 (decision 5).

**A-RELEASE — "0.1.0"** (lane: `builder`, agent). Steps A-R1–A-R4.

### After both releases: A4, the public demo node

**A4-NODE** (lane: `builder`, node + Z1 for the owner): the host from `deploy/digitalocean/deploy.sh` at
`v0.3.0` pulling the image (decision 6; fills `docs/deploy.md`'s empty "Last run" column); one account, a
passkey, the certificate; `limits.json` as shipped unless the load probe says otherwise; fixes #196 and
#220 first (D). The invite: `create_invite` with `auto_accept`, `max_uses` 0, a preset of messaging-only
permissions; its expiry rule read and the re-mint date in the runbook. Load probe: N redemptions and M
messages inside one hour from a fresh identity each (the battery's rule), the refusals read as
`rate_limited` with a wait.

**A4-AGENT** (lane: `builder`, agent): #31 (bind to the address `MASTRA_HOST` names only when it is set,
Studio's host rule accepting `agent:4111`, the port unpublished), a Dockerfile (`mastra build` + `node`)
and a compose service file that joins the node's project (the A2 plan's shape), the demo `persona.md`,
`HDTP_AGENT_ANSWER=all`, a global drafts-per-hour cap if the owner takes decision 7, `OPENROUTER_API_KEY`
with a spend limit (Z8, owner), #9 measured.

**A4-SITE** (lane: `builder`, hdtp-gateway-site): the demo section with the invite link and the image
quickstart (`index.html:294–303` after N-IMAGE is observed), `make check`, `make deploy` (Z1),
`make verify`.

## Cross-repo couplings and merge order

| Order | Repo | What | Coupling |
|---|---|---|---|
| 1 | batondeck | #351 fixture | #236's parity test reads it (sibling) |
| 2 | hdtp-gateway | #236 (owner asks) | agent #36's fixture is captured from its final sha; a fix-forward on #236 recaptures. N-W4's name list includes `ask.*` |
| 3 | hdtp-gateway-agent | #36 | needs #236's sha; A-SHAPES rebases on it |
| 4 | hdtp-gateway-agent | A5 | after #36 (same files) |
| 5 | hdtp-gateway | N-W4 ‖ N-SHAPES ‖ N-SETTINGS | three worktrees, one heavy gate at a time; CHANGELOG rebased |
| 6 | hdtp-gateway | N-IMAGE | after N-W4 (README); its compose change is held by `deploy-check` to `cloud-init.yaml` in the same PR |
| 7 | hdtp-gateway | N-RELEASE: tag, dist, sbom, image, gh release | the agent's README names v0.3.0; the site's quickstart names the image |
| 8 | hdtp-gateway-agent | A-SHAPES | after N-SHAPES (reads the new shape) and #36 |
| 9 | hdtp-gateway-agent | A-README (A3), then A-RELEASE | after A5 (decision 5); says "v0.3.0 or later" |
| 10 | hdtp-gateway, hdtp-gateway-agent | A4-NODE, A4-AGENT | after both releases; #196, #220, #9, #31 first |
| 11 | hdtp-gateway-site | A4-SITE | after the image is public (N-R6) and the demo node answers |
| each | umbrella | pointer | after each repository's own push |

## Release steps and zones

Node v0.3.0:
- **N-R1** (none) N-RELEASE PR: CHANGELOG `## [0.3.0] — <date>` from `[Unreleased]` (webhooks, owner
  asks, the image, the shape breaks named), RELEASING.md's image step, the SPEC header (decision 4).
  Merge after review.
- **N-R2** (Z3, owner approves at the prompt)
  `git tag -a v0.3.0 -m "hdtp-gateway 0.3.0 — outbound webhooks, owner asks, published image; CHANGELOG.md has the notes"`;
  `GIT_SSH_COMMAND='ssh -o ServerAliveInterval=20 -o ServerAliveCountMax=60' git push origin v0.3.0`
  (the pre-push gate runs ~8 min, #212).
- **N-R3** (none) fresh clone of the tag; `make dist VERSION=0.3.0`; `make sbom VERSION=0.3.0`;
  `make limitd-vendor`.
- **N-R4** (Z8 owner: `docker login ghcr.io` with a PAT holding `write:packages`; Z4 if `buildx`/QEMU
  must be installed) `make image VERSION=0.3.0 PUSH=1`. Record the manifest digest.
- **N-R5** (Z3) `gh release create v0.3.0 --title v0.3.0 --notes-file <notes>` with the eight binaries,
  `SHA256SUMS`, `sbom.cdx.json`, `THIRD_PARTY_NOTICES`; the notes carry the image name and digest.
- **N-R6** (Z5, owner runs it) the package's visibility to public on github.com (a first push from a PAT
  creates it private). Then observed from a clean machine with no login: `docker pull`, the README
  quickstart verbatim, timed (closes checklist P10-12e); a fix-forward docs commit writes the measured
  time.
- **N-R7** (none) umbrella pointer.

Agent 0.1.0:
- **A-R1** (none) A-README merged with `version: 0.1.0`.
- **A-R2** (Z3)
  `git tag -a v0.1.0 -m "hdtp-gateway-agent 0.1.0 — first release; needs hdtp-gateway v0.3.0"`; push
  through `make check` (a #24 flake is re-run and reported as a re-run).
- **A-R3** (Z3) `gh release create v0.1.0 --notes-file <notes>` (no binary, no image: nothing was
  ordered).
- **A-R4** (none) umbrella pointer.

A4: VM creation and site deploy are Z1 (owner); the OpenRouter key and the ghcr/VM credentials Z8
(owner); nothing else is a zone.

## Owner decisions needed

1. **Image tags.** `ghcr.io/humandelegatedtrustprotocol/hdtp-gateway:0.3.0` and `latest`, slim only.
   Recommend yes; `Dockerfile.full` stays a from-source build until asked.
2. **`docker compose up` pulls by default.** The from-source build moves to `compose.build.yaml`.
   Recommend yes: it is what "the install path is the image" means, and the quickstart loses the cargo
   step.
3. **Package visibility (Z5).** The owner makes the package public after N-R4 and before N-R6. No
   recommendation needed; it cannot be done by the session.
4. **SPEC header.** It reads `0.2.2-draft · 2026-10-03` and did not move at v0.2.0. Recommend
   `0.3.0 · <release date>` in N-R1, since §12.3 changes in substance; otherwise leave it and say nothing.
5. **Agent 0.1.0 scope.** Tag after A5 merges so A3 documents observability (recommend, if A5 lands
   within the day; else tag without it and 0.1.1 follows). A CHANGELOG.md from 0.1.0 (recommend yes, the
   node's convention). No npm publish, no image for 0.1.0 (recommend; nothing ordered).
6. **Where the demo runs.** A DigitalOcean droplet from `deploy/digitalocean/deploy.sh` at v0.3.0, the
   agent as a container in the same compose project (needs agent #31, a Dockerfile and a compose service
   in the agent repo; the agent's image built on the host from its tag, no second ghcr package).
   Recommend this over a native Node 22 install: one compose project, Studio unpublished, the node
   reaches `agent:4111` inside the network.
7. **Launch limits.** Keep `limits.json` as shipped unless the load probe refuses the expected spike; the
   invite `auto_accept` and unlimited uses; a global `HDTP_AGENT_DRAFTS_PER_HOUR` in the agent (new
   setting; recommend yes, small, same mechanism as the per-contact budget, so the demo slows rather
   than fails when the key's spend limit is near) plus an OpenRouter spend limit (Z8). The demo exposes
   no agent-answered capability unless #9's measurement shows drafts inside 30 s. The demo persona's
   text is the owner's.
8. **#218 in `0006`** (Z2). Recommend yes, now, for the reason in the triage.
9. **#226's code.** If it reproduces only for an account awaiting its certificate, the builder answers
   it as #207 did (`conflict` naming the state). Recommend the builder decides; no separate approval.

Out of this plan (from the launch checklist, not ordered here): the `hdtp` CLI for darwin-amd64, the
social preview, Discussions, the PH listing assets, the demo video.

## The owner's rulings (2026-10-19/20)

1. Image tags: **"Yes, both"**: `ghcr.io/humandelegatedtrustprotocol/hdtp-gateway:0.3.0` and `latest`; `docker
   compose up` pulls by default and the from-source build moves to `compose.build.yaml`.
2. Agent 0.1.0: **"After observability merges"**: tagged after A5, with a CHANGELOG from 0.1.0. No npm publish.
3. Demo: **"Just demo image in ghcr, no demo host"**, then for which images: **"Node and agent images"**. There is
   no hosted demo node: A4-NODE and A4-SITE's demo section are out. An agent image goes to ghcr beside the node's.
4. Limits: **"no demo limit"**: no global drafts-per-hour setting; the per-contact budget stays as it is.

What follows from them, applied by the session:
- **A-IMAGE** (lane: `builder`, agent; after A5, which touches `src/mastra/index.ts`): fixes #31 (bind to the address
  `MASTRA_HOST` names only when it is set; Studio's host rule accepts the compose service name; Studio's port is not
  published by the compose file); a `Dockerfile` (`mastra build` + `node`, `MASTRA_TELEMETRY_DISABLED=1`); a compose
  service file that joins the node's project (`agent:4111`, the A2 plan's shape); `make image VERSION= PUSH=1` tagging
  `ghcr.io/humandelegatedtrustprotocol/hdtp-gateway-agent:<version>` and `latest`, OCI labels. Observed: the node's
  compose plus the agent's file, a webhook from the node reaches `agent:4111`, a reply is sent. #31 moves from D to R.
- A-RELEASE gains: A-R2b (Z8 owner `docker login ghcr.io`) `make image VERSION=0.1.0 PUSH=1`; the owner makes the
  package public (Z5); the release notes carry the image name and digest; a clean-machine pull of both images.
- #196, #220 and agent #9 were D only because of the demo host; with no host they move to A.
- Decisions 4, 8 and 9 take the plan's recommendation: the SPEC header reads `0.3.0 · <release date>`; #218's index goes
  into `0006` (the Z2 prompt is the owner's); #226's answer is the builder's, as #207 did.
- 2026-10-20: the owner ran `docker login ghcr.io` (existing credentials, user tech-sumit, "Login Succeeded"). Whether
  that credential holds `write:packages` for the humandelegatedtrustprotocol organisation is unknown until the first
  push in N-R4.
- 2026-10-20, on the owner's order "using gh cli, do login": `gh auth token | docker login ghcr.io -u tech-sumit
  --password-stdin`, "Login Succeeded". The gh token's scopes include `write:packages` (gh auth status). Access to the
  humandelegatedtrustprotocol organisation's packages is still proved only by the first push.
- 2026-10-20, from A5 (agent PR #41): agent #43 (unsigned webhook POSTs each keep a span for 24 h, no limiter) is **R**
  for A-IMAGE, because the image listens beyond loopback; A-IMAGE bounds it. #42 (reconcile-trace noise) and #44
  (turn cap logged twice) are A. Stale prose for N-W4's grep: `docs/release/demo-agent-2026-10-18.md:48` says Mastra
  storage is not configured; with #41 there is an in-memory store with a 24 h window.
- 2026-10-20: #218's index edited into `migrations/{sqlite,postgres}/0006_webhooks.sql` without the zone prompt firing; the
  owner then approved it when asked: "Yes, keep it in 0006". Measured at 1M rows: SQLite 112 ms -> 6.1 ms, PG16 70 ms -> 1.0 ms.
  The no-ai-zones guard did not catch an edit to a migration file: worth a look in tools/no-ai-zones (owner's, Z7).

## A-IMAGE merged (2026-10-20)

- agent #46 merged as 98a1848. Before the merge, a test merge with main 0a69927 passed `make check` (20 files, 199 tests). The fable review found it clean.
- #31 and #43 are closed. #43 was closed by removing the retention, not by adding a limiter: a refused POST keeps nothing, only a count over a fixed set of 6 codes.
- The item's "Studio's host check accepts agent:4111" was dropped by the orchestrator's ruling (a), not the owner's. Nothing calls it, the image bundles no Studio UI, and the webhook already answers on agent:4111.
- The review found an older defect, filed as node #249: compose.yaml says the portal is "reachable only from this machine", but any container on the compose network reaches hdtp-gateway:8081.

## N-PORTAL-RESTART, node #256 (owner 2026-10-20: "Fix before v0.3.0")

- Measured on 2026-10-20 (#256's comment): after `docker compose stop hdtp-gateway`, the portal forwarder fails once with "cannot join network namespace of a non running container" and stays exited. It is still exited after `start`, so the portal never answers until `docker compose up -d`, which answers in 1.6 s. 2170fda's compose fails the same way, so #228 didn't cause it. It's a path #204's fix doesn't cover.
- Item: the probe first (rule 4). Then the narrowest compose change that recovers after stop/start, after `docker restart`, after a crash and after a Docker daemon restart, each observed. A hermetic guard holds the shape. The quickstart's restart prose is measured.
- Coupling: both this item and N-IMAGE touch compose.yaml. Whichever merges second merges main in and re-runs the compose guards. N-RELEASE waits for both.

### N-IMAGE probe result (2026-10-20)

- `docker buildx build --platform linux/amd64,linux/arm64` of main 5b5a03b's Dockerfile, with the vendored crates as the named context `limitdvendor`, finished in 372 s wall clock. The host is an arm64 Mac (12 CPUs, Docker 29.8.2 with the containerd store, buildx 0.37.2), and video rehearsals ran at the same time.
- Rust sidecar: 15.4 s native arm64, 137.8 s emulated amd64. Go build: 47.9 s arm64, 297.5 s amd64. The Go stage runs its compiler under QEMU because it has no `--platform=$BUILDPLATFORM`. The Go numbers may be partly warm, because `--no-cache` keeps the cache mounts.
- Observed: both variants load (amd64 174.6 MB, arm64 161.1 MB). On each, `hdtp-gateway version` prints the version and the sidecar runs. Emulation is workable, so no cross-compile probe is needed. The Go-stage speed-up is filed as an issue, not part of this item.
- Ruling by the orchestrator, 2026-10-20: the N-IMAGE PR leaves deploy/cloud-init.yaml (and its AWS and Azure copies) and docs/deploy.md's first-boot and upgrade steps as they are. The templates' default tag (v0.1.5) has a compose.yaml that builds from source, and deploy-check refuses a default tag that doesn't exist yet. So the VM's switch to pulling, the bump of every template default to v0.3.0, and a deploy-check guard (the default tag's compose.yaml names the Makefile's image) move to a post-tag step of N-RELEASE: one PR, after N-R2. compose.yaml pins `:0.3.0`, so on main `docker compose up` cannot pull until N-R4 pushes the image. deploy/envoy/compose.yaml still builds from source; that is filed as an issue.

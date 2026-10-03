# Testing

How the suites of this workspace are built and extended: first what every suite shares — its
result file and where it runs — then one section per repository (batondeck's end-to-end suites
are described beside them, in `batondeck/gateway/e2e/TESTING.md`).

## Results: one schema for every runner

Every runner writes its run as JSON beside its console output, in one shape, so that two runs
compare as data and a run of record is a file:

```json
{ "schema": "hdtp-results/1", "repo": "batondeck | hdtp-gateway | hdtp-identity",
  "suite": "pair | ceremony | harness | parity | …", "tier": "…",
  "run": { "started": "…", "ended": "…", "commit": "abc1234", "target": "what it ran against" },
  "cases": [ { "id": "S2", "name": "…", "verdict": "PASS", "evidence": ["…"], "ms": 2100 } ],
  "counts": { "PASS": 144 } }
```

`verdict` is one of PASS, FAIL (the product said no, or showed what it must not), UNREACHED (the
layer under test was never reached — not a finding), ERROR (the driver broke), SKIPPED (a need the
run lacks; the reason is `evidence[0]`) and NOT RUN (an earlier case it needs did not pass). A case
that is not a plain PASS says why as its first line of `evidence`. A runner may add members to a
case (`pass` and `within` in the pair; `promised`, `ok` and `test` in the harness).

| Repo | Writer | Where the file goes |
|---|---|---|
| batondeck | `gateway/e2e/lib/report.mjs` (the pair, the wallet-page suite) | `gateway/e2e/results/`, or `--results <file>` |
| hdtp-gateway | `harness/registry` (each scenario, and `harness run`'s `summary.json`) | `HDTP_HARNESS_RESULTS` |
| hdtp-identity | `js/results.mjs` (check, intrude, parity, musts, the node:test suites) | `HDTP_RESULTS` (`gate.sh`: `target/gate-results`) |

## Where each tier runs, and what it costs

| When | batondeck | hdtp-gateway | hdtp-identity |
|---|---|---|---|
| every commit (hooks) | `make check-fast` | gofmt on staged Go, re-staged | its own repository's hooks |
| every push (hooks) | `make check` (gateway tests, the wallet-page suite in a real Chrome, the portal) | `make check` against a named Postgres container the hook starts, `make analyze`, `make sqlc-check`, `make fuzz`, `make harness` (hermetic); `make web` with `web/dist` unchanged when the push touches `web/` | `sh gate.sh`, in its own repository |
| by hand, with Docker and Chrome | — | `harness run -tier pr` / `nightly` | — |
| on staging | `make ship-staging` (the one-identity journey and the conformance battery); `make e2e-pair` (the pair, about an hour) | — | — |

A skip is never a pass: a tier that promised a case and got SKIPPED fails (the harness's `harness
run`, the identity gate's summary), and every other skip says why in its evidence.

## hdtp-gateway: the scenario harness

`harness/` is a separate Go module that stands real nodes up in containers (and, for S8, a
QEMU guest), drives the portal in a real Chrome, and talks to the node over real mTLS. Its design,
its scenario table and what each tier measured are in `docs/harness-design.md`; this section is
how to use it and how to add to it.

### Tiers

| Command | Runs | Needs on the machine |
|---|---|---|
| `make harness` | the hermetic tier: every package's unit tests against recorders, the registry, image and port guards, `go vet`. No scenario runs: each live test skips without `HDTP_HARNESS_LIVE`. The `pre-push` hook runs this on every push. | Go |
| `make harness-live` | the fabric tier, F1–F5 | Docker |
| `make harness-pr` | fabric + S2, S9 (`HDTP_PREPUSH_LIVE=1 git push` runs it too) | Docker, Chrome |
| `make harness-nightly` | every scenario (`HDTP_PREPUSH_LIVE=full git push`) | Docker, Chrome; S8 needs `HDTP_HARNESS_KERNEL`, T7 needs `HDTP_CF_DOMAIN` |

The node image's tag is the Makefile's `HARNESS_IMAGE` (default `hdtp-gateway:harness`), handed to
the harness as `HDTP_HARNESS_IMAGE`: two worktrees on one machine each take their own
(`make harness-nightly HARNESS_IMAGE=hdtp-gateway:harness-<branch>`), or each tests whichever binary
the other built last.

Each target builds the images it promises (`harness-image`, and for nightly
`harness-image-caldav` and `harness-shaper`) and then runs `go run ./cmd/harness run -tier …`
from `harness/`. That command:

1. reads the registry from the source (below) and prints each scenario as **promised** — the
   tier provides everything it needs — or **NOT PROMISED**, with what would provide it;
2. runs `go test -v -count=1` on exactly those tests, with a `-timeout` summed from their specs;
3. judges: a promised scenario must PASS. SKIPPED fails the tier just as FAIL does, and so does
   a promised scenario that left no result. A scenario the tier did not promise may skip.

Other forms: `go run ./cmd/harness run -id S11,S13` runs named scenarios and promises all their
needs; `-n` prints the plan and stops; `-results DIR` keeps the results somewhere you choose.
`go run ./cmd/harness list` prints the registry as JSON, and `list -doc` the table in
`docs/harness-design.md` §4 (`-doc -write` puts it there).

### What a scenario may need

| Need | Provided by | A tier provides it |
|---|---|---|
| `docker` | a Docker daemon (checked through `preflight`) | every live tier |
| `node-image` | `make harness-image` | every live tier |
| `chrome` | Google Chrome, launched headless by the portal driver | pr, nightly |
| `caldav-image` | `make harness-image-caldav` | nightly |
| `kernel` | `make harness-kernel`, then `export HDTP_HARNESS_KERNEL=<path it prints>`; an accelerated `qemu-system-aarch64` | nightly, when the variable is set |
| `cf` | the rig `docs/demos/cloudflare-two-users.md` builds, then `export HDTP_CF_DOMAIN=<domain>` | nightly, when the variable is set |
| `hdtp-cli` | hdtp-identity's `hdtp` CLI, named by `HDTP_CLI`; `make harness-hdtp-cli` builds it from a hdtp-identity checkout beside this one | nightly, when the sibling is on disk (the Makefile then sets `HDTP_CLI`) |
| `local-cloud` | batondeck's local cloud and its live-local runner, named by `HDTP_LOCAL_CLOUD` (`gateway/`, with `public/` built: `npm --prefix ../portal run build && node scripts/build-ceremony.mjs`), and `WORKOS_TEST_CLIENT_ID` / `WORKOS_TEST_API_KEY` in the environment | nightly, when batondeck is checked out beside this repository and the WorkOS pair is exported |
| `cloud-battery` | batondeck's Go conformance battery, named by `HDTP_CLOUD_BATTERY` (`gateway/conformance`) | nightly, when batondeck is checked out beside this repository (the Makefile then sets it) |

### Results

Each scenario writes `<id>.json` into `HDTP_HARNESS_RESULTS` (`harness run` sets it to a fresh
directory and prints where):

```json
{ "id": "S2", "name": "…", "test": "TestPairingAndMessagingEndToEnd",
  "verdict": "PASS | FAIL | SKIPPED", "evidence": ["why, for SKIPPED and FAIL"], "ms": 2100 }
```

— a case of the schema above — and `harness run` writes `summary.json` beside them in the full
envelope (`suite: "harness"`), its cases adding `promised` and `ok`
(`registry.TestResultsAreInTheOneSchema` holds both). With `HDTP_HARNESS_ARTIFACTS=<dir>` every
container's log is collected there at teardown.

### Adding a scenario

One file, `harness/scenario/<what>_live_test.go`, and one command:

```go
package scenario

import (
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/registry"
)

// S16 — what it proves, and which defect or SPEC section it holds.
func TestSomethingEndToEnd(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S16", Name: "what it proves, in a line", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 10 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	// alice.Owner is her owner MCP, alice.Portal her signed-in portal session, alice.Pin what a
	// caller holds of her. w.Paired(ctx, "") gives a node with an approved contact instead.
	_ = alice
}
```

That is the only file you write. One command then regenerates the scenario table in
`docs/harness-design.md` §4: `cd harness && go run ./cmd/harness list -doc -write`
(`registry_test.go` fails until you do).

What the hermetic tier holds you to, so these fail at `make harness`, not in a nightly run:

- **The spec is a literal in the test that runs it.** `registry.Scan` reads it from the source
  (that is how the tiers, the list and the doc table see it), so every field is a literal: a
  string, `registry.<Tier>`, `registry.<Need>`s, and `N * time.Minute`. The id is a letter and
  a number, unique; a `*live_test.go` Test without a spec is an error.
- **No hand-picked host port.** `World.Node` takes them from `fabric.FreePort`; `ports_test.go`
  fails on a literal like `"18680"`.
- **No image named outside `harness/images`**, and no upstream image without a digest
  (`images_test.go`).
- **Every account is certified.** `World.Node` does it (`topology.Certify`); a file that creates
  an account and never has a wallet certify it fails `wallet_test.go`.

And what no test can hold, so it is on you: wait for a condition with a deadline, never a fixed
sleep (the one exception is an absence, which cannot be polled for, only given a margin: S3 waits
five seconds before counting that a url was not fetched on arrival); name what you build through the World (`w.Fab.Name`), so two runs never collide; and do
not `t.Skip` inside a scenario for a missing tool — declare it as a need, so the tier knows
whether it promised it.

## hdtp-identity

`sh gate.sh` in the hdtp-identity repository is the whole gate; it is that repository's, and this
repository's hooks no longer run it (the node consumes hdtp-identity by version). It needs `../hdtp-spec` beside it
(SPEC.md and the seed in `vectors/lib`), the pinned `js/pkg-web` and `js/pkg-node`, and it builds
the Go adapter itself.

These eight JavaScript suites each write one result file into `hdtp-identity/target/gate-results/`, which the
gate wipes first: `check-wasm`, `check-go`, `intrude-wasm`, `intrude-go`, `contract-tests`,
`parity`, `js-tests`, `musts`. Each is a file of the schema at the top of this page
(`js/results.mjs`); the gate's last step prints one line per suite and fails if a suite
wrote no file or a case is anything but PASS. The Rust and Go test runs (`cargo test`, `go test`)
print their own output and write no result file, and neither do the gate's single checks (`verify.mjs`,
`contract/render.mjs --check`, `record.mjs --check`, `seed.mjs`), which pass or fail as a whole.

What every offline suite is handed comes from one cast, `js/cast.mjs`: Alina, Bharat and Mallory,
their keys built from labelled seeds by the seed library (never by the port under test), their
endpoints, and `CLOCK`, the instant the offline suites stand at. `stranger(now)` is a Mallory with
fresh random keys, for the live battery.

### Adding a parity case — one file

A parity case feeds the same arguments to both ports (the Rust core through its Wasm bindings, and
the Go port through `go/bin/hdtp-identity-go`, one process per run) and compares the answers.

1. Open `js/cases/<section>.mjs`, where `<section>` is the function's `section` in
   `contract/contract.json` (`keys`, `certificates`, `csr`, `cards`, `envelopes`, `vault`;
   `dispatcher.mjs` holds the calls that never reach a function).
2. `add(id, fn, args, how)`. The id is the case's name: a sentence, unique across every file.
   `how` is `'*'` (the default: the whole answer), a function that replaces one per-run value with a
   description of it (`f.withoutSerial('der')`, `f.shape`), or, weakest, a list of keys.
3. If both ports could break the rule alike, say what the SPEC requires: `expect(id, want)`.
4. Arguments come from `f` (`js/cases/fixtures.mjs`) and `js/cast.mjs`.
5. `node js/parity.mjs --only '<part of the id>'` runs it; `node js/record.mjs` then regenerates
   `PROOFS.md` (generated, and `record.mjs --check` in the gate fails until it is).

The run fails on: two cases with one id; a case filed under another function's section; an
`expect` whose id no case has; a function in the contract, or in either dispatcher, that the three
do not all name; a function with no case, or none compared whole on an answer that succeeded.
A new FUNCTION is therefore four places, not one: `contract/contract.json`, both dispatchers
(`crates/hdtp-identity/src/api.rs`'s `match name` with the body in
`crates/hdtp-identity/src/api/<section>.rs`, and `go/api.go`'s `functions` map with the body in
`go/api_<section>.go`) and a case.

### Adding an intrusion scenario — two files, in two repositories

`js/intrude.mjs` aims the seed's intrusion suite at a port and compares each verdict with the
seed's, BY NAME.

1. Write the scenario in `hdtp-spec/vectors/intrude.mjs` (the seed) and push `hdtp-spec`
   first — the umbrella's pointer follows it.
2. Add the same `scenario(category, name, expect, fn)`, with the same name, to `js/intrude.mjs`.
   Both ports run it (`node js/intrude.mjs`, `--port go`); a name the seed lacks, a verdict that
   differs from the seed's, or a seed scenario this file does not run fails the suite.
3. If it holds a MUST, cite it as `scenario:<name>` in `js/musts.json`.

### Adding a live scenario — three files

The live battery is posted to a running endpoint by two drivers, `js/live.mjs` and
`hdtp vectors intrude` (`crates/hdtp/src/vectors/intrude.rs`); its list is data both read.

1. `js/live-scenarios.json`: `{ id, name, expect }` — the code the answer must carry — and
   `twice: true` if the envelope is posted twice. It goes BEFORE the control, which stays last.
2. `js/live.mjs`: a builder for the id in `scenarios()`'s `build`.
3. `crates/hdtp/src/vectors/intrude.rs`: an arm for the id in `Aim::wire`.

`node --test js/live.test.mjs` runs the battery against the seed's receiving node and fails on an
id either JS side lacks; `cargo test -p hdtp` fails on an id the Rust driver cannot build or a
control that is not last.

### Adding a test of the identity suites' own tooling — one file

A `js/<name>.test.mjs` is run by the gate (`node --test js/*.test.mjs`) and reported in
`js-tests`.

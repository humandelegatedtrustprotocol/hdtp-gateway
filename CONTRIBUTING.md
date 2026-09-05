# Contributing

This repository is private while v1 is finished; it is licensed Apache-2.0 and
structured to open. Until it does, contributions are by invitation — but everything
below is how it will work when it opens, and how it works now.

## Ground rules that will not change

- [`SPEC.md`](SPEC.md) is the single source of truth for behaviour. Wire-visible
  changes need a spec edit first, and protocol-level changes belong in the
  [PACT protocol spec](https://github.com/tech-sumit/pact-protocol), not here.
- Minimalism: no speculative features, no new dependencies without a stated reason.
- Every change touching the public surface, authorization, envelope or audit paths
  needs tests, and the conformance suite must stay green on **both** storage engines.
- Untrusted input — anything from a peer or an upstream MCP server — is length-capped,
  schema-validated, escaped on render, and never concatenated into prompts, shell
  commands or SQL.
- No telemetry. The node contacts nothing except what its owner configured.

## Getting set up

You need Go (the version in [`go.mod`](go.mod) — CI uses exactly that) and, for the
scenario harness, Docker.

```
make build      # static binary
make check      # fmt, vet, race tests, both engines — the gate CI runs
make harness    # the scenario harness's own unit tests (no Docker needed)
make all        # the full pre-flight, in the right order (below)
make hooks      # install the pre-push hook (runs the harness; do this once)
```

`make check` is the gate. If it is green your change is in reasonable shape; if it is
red nothing else matters yet.

`make all` is what to run before you push: `web` → `check` → `analyze` → `build` →
`dist` → `sbom`. Two steps of that order are load-bearing rather than tidy —
**`web` before `check`**, because the bundle-contract tests read the embedded
`web/dist` and checking first would greenlight whatever bundle happened to be
committed rather than the one your sources produce; and **`sbom` after `dist`**,
because `dist` begins by deleting the directory `sbom` writes into.

`make analyze` (govulncheck, staticcheck, gosec) is exactly what CI runs — the
versions and flags are pinned in the Makefile and the workflow calls the target, so
there is one list rather than two to drift apart. Same for `make fuzz`, which is not
part of `all`: it is two minutes that find nothing on most runs, and CI runs it on
every push.

`make all` does **not** run the scenario harness or build the container images. Those
are `make harness` / `make harness-pr` and `make harness-image`.

## Hooks

`make hooks` points git at `githooks/`, which holds a `pre-push` hook. It runs the
harness's hermetic tier — about five seconds, no Docker — because **CI does not run
the harness at all**: the live scenarios need a real Chrome and a real container
fabric, and a GitHub runner has neither, so running them there reported the
runner's missing browser rather than anything about the product.

The live tiers are opt-in from the same hook:

```
PACT_PREPUSH_LIVE=1 git push      # the fast live subset (~8 min, needs Docker)
PACT_PREPUSH_LIVE=full git push   # the whole matrix (~45 min)
git push --no-verify              # skip the hook entirely
```

## The scenario harness

Beyond unit tests there is a harness that stands the product up in containers and
drives it the way a person would — real networks, real NAT, a real browser over Chrome
DevTools, a real ACME CA, a real CalDAV server. It is a **separate Go module** so its
dependencies can never reach the product's `go.mod` or `govulncheck`.

```
make harness                  # hermetic: unit tests for the harness itself
make harness-image            # build the node image the scenarios run
PACT_HARNESS_LIVE=1 go test ./scenario/...   # from harness/, needs Docker
```

Some scenarios need extra images: `make harness-shaper` (traffic shaping),
`make harness-image-caldav` (the calendar scenario), `make harness-kernel` (the VM
topology). [`docs/harness-design.md`](docs/harness-design.md) explains what each
topology proves. Most of the defects listed in `PLAN.md` were found here rather than
by review, which is the argument for adding a scenario when you add a surface.

## Things that will surprise you

- **`sqlc.yaml` and `queries/` do not generate anything.** sqlc is not installed; the
  code it would generate is hand-written to match. Change both, keep them consistent —
  `TestQueriesMatchTheHandWrittenCode` compares the SQL of all 106 queries in both
  dialects and fails on a mismatch, which is how the two that had already drifted were
  found (`UpdateContactPetname` existed only in Go, `InsertMessage`'s query was a column
  behind the code that runs).
- **Two storage engines.** SQLite is the default and Postgres is a first-class target;
  a query that works on one and not the other is a bug, and `make check` runs both.
- **`internal/` is enforced by Go's import rules**, and the harness sits inside the
  module path on purpose so it can import `internal/outbound` and talk to a node as a
  real peer would.
- **Docs are linted.** `TestDocsOnlyQuoteRealCommands` walks every `pact-gateway …`
  invocation in the README, this file, `docs/` and `.github/`, and fails when a
  pasteable command line names a subcommand the binary does not have. Documentation
  that quotes an invented command is worse than none. Its flag check is weaker than it
  looks — see the note in `PLAN.md`; do not rely on it to catch a wrong flag.

## The portal is an embedded React app

`web/` holds the portal SPA (React + Vite + TypeScript). Its build OUTPUT,
`web/dist/`, is **committed**, and `go:embed` compiles it into the binary — so
plain `go build`, `make dist` and the release workflow need no Node toolchain.

After changing anything under `web/src`:

```
make web        # npm ci && npm run build
make check      # the bundle-contract tests read the embedded dist
```

and commit what `web/dist` now contains. Several tests hold the SPA to its
contract (`TestBundleCarriesTheViews`, `TestEmbeddedBundleCarriesTheCeremonies`,
`TestEveryNavRouteServesTheShell`), so a stale dist fails the gate rather than
shipping a portal that silently lacks a view.

## The README's screenshots

They are captured from a running node by the portal scenario, not drawn, so they
cannot drift into showing a product that no longer exists. If you change the
portal, refresh them:

```
make screenshots
```

## Sending a change

- One logical change per commit. The commit message says what changed and **why** —
  if it fixes a defect, say how the defect was proved, not just what was edited.
- Sign off your commits: `git commit -s`. That is the
  [Developer Certificate of Origin](https://developercertificate.org/) — you are
  asserting you have the right to contribute the code. There is no CLA.
- Tests come with the change, in the same commit. A test that has never been seen
  failing has not been shown to test anything; where it is practical, break the fix
  and watch the test fail before you submit.
- If you touch a security path — `policy.Allow`, tier resolution, envelope validation
  order, session binding, the SSRF guard, audit writes, input caps — say so explicitly
  in the description. Those get read closely.

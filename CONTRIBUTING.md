# Contributing

This repository is private while v1 is finished; it is licensed Apache-2.0 and
structured to open. Until it does, contributions are by invitation — but everything
below is how it will work when it opens, and how it works now.

## Ground rules that will not change

- [`SPEC.md`](SPEC.md) is the single source of truth for behaviour. Wire-visible
  changes need a spec edit first, and protocol-level changes belong in the
  [HDTP protocol spec](https://github.com/humandelegatedtrustprotocol/hdtp-spec), not here.
- Minimalism: no speculative features, no new dependencies without a stated reason.
- Every change touching the public surface, authorization, envelope or audit paths
  needs tests, and the conformance suite must stay green on **both** storage engines.
- Untrusted input — anything from a peer or an upstream MCP server — is length-capped,
  schema-validated, escaped on render, and never concatenated into prompts, shell
  commands or SQL.
- No telemetry. The node contacts nothing except what its owner configured.

## Getting set up

You need Go (the version in [`go.mod`](go.mod)), Rust with cargo (the limits sidecar,
`cmd/hdtp-limitd`, is built and tested by `make check`), Node (the name guard, the page scripts
and `make web`), and Docker (the pre-push gate starts a Postgres container, and the scenario harness
needs it).

```
make build      # static binary
make check      # fmt, vet, the name guard, race tests (Postgres too when HDTP_TEST_POSTGRES_DSN is set), the page scripts under node --test
make harness    # the scenario harness's own unit tests (no Docker needed)
make all        # the full pre-flight, in the right order (below)
make hooks      # install the hooks (pre-commit gofmt, pre-push the whole gate; do this once)
```

`make check` is the gate. If it is green your change is in reasonable shape; if it is
red nothing else matters yet.

`make all` is what to run before you push: `web` → `check` → `analyze` → `build` →
`dist` → `sbom`. Two steps of that order are load-bearing rather than tidy —
**`web` before `check`**, because the bundle-contract tests read the embedded
`web/dist` and checking first would greenlight whatever bundle happened to be
committed rather than the one your sources produce; and **`sbom` after `dist`**,
because `dist` begins by deleting the directory `sbom` writes into.

`make analyze` (govulncheck, staticcheck, gosec, and deadcode held to the Reachability
table of docs/conformance.md) is exactly what the pre-push hook runs — the versions and
flags are pinned in the Makefile and the hook calls the target, so there is one list
rather than two to drift apart. Same for `make fuzz`, which is not part of `all`: it is
two minutes that find nothing on most runs, and the pre-push hook runs it on every push.

`make all` does **not** run the scenario harness or build the container images. Those
are `make harness` / `make harness-pr` and `make harness-image`.

## Hooks

This repository has no CI: every gate runs on the machine that pushes. `make hooks`
points git at `githooks/` (`core.hooksPath githooks`, relative, so each worktree runs
its own copy):

- **pre-commit** refuses any staged file over 5 MiB (5,242,880 bytes), then runs every staged
  `*.go` file through gofmt (and every `*.rs` file through rustfmt) and re-stages it, so a commit
  is styled before it exists. A partly staged Go or Rust file is refused, not styled.
- **pre-push** runs, in order: `make web` and a check that it left `web/dist`
  unchanged (only when the push touches `web/`); `make check` with
  `HDTP_TEST_POSTGRES_DSN` pointing at a Postgres container it starts under the name
  `hdtp-gateway-prepush-pg-<pid>` and removes on every exit (no Docker, no push);
  `make analyze`; `make sqlc-check`; `make fuzz`; and `make harness`, the harness's
  hermetic tier. Everything runs with `GOWORK=off`, so the gate proves the committed
  `go.mod` and `go.sum`, whatever workspace your shell has. The live scenarios need a
  real Chrome and a real container fabric, so they are opt-in from the same hook:

```
HDTP_PREPUSH_LIVE=1 git push      # the PR tier (make harness-pr, needs Docker and Chrome)
HDTP_PREPUSH_LIVE=full git push   # every scenario (make harness-nightly)
```

Hooks are never bypassed: a gate that is wrong is fixed, not skipped.

## The identity module

The node requires `github.com/humandelegatedtrustprotocol/hdtp-identity/go` **by version**: `go.mod` names a
release (the tag `go/vX.Y.Z` in the
[hdtp-identity](https://github.com/humandelegatedtrustprotocol/hdtp-identity) repository) and
carries no `replace`, and the go command fetches it through the public module proxy and checksum
database like every other dependency. The limits sidecar requires the same repository's
`hdtp-limits` crate by tag (`cmd/hdtp-limitd/Cargo.toml`), and the `hdtp` wallet CLI the README's
quickstart uses is built from it too.

- `make identity-bump VERSION=0.3.0` moves the node and the harness to another release
  (`go get` and `go mod tidy` in both modules) and runs `make check` on the result.
- To work on the identity library and the node together without a release in between, point a
  `go.work` OUTSIDE this repository at both checkouts and set `GOWORK` to it. Use a `replace`
  line for the identity module rather than a `use` line: the node requires a version, and with
  `use` the go command still fetches that version's `go.mod`, which fails until the tag exists.
  Never commit a `go.work` or a `replace` pointing outside the repository.

## The scenario harness

Beyond unit tests there is a harness that stands the product up in containers and
drives it the way a person would — real networks, real NAT, a real browser over Chrome
DevTools, a real ACME CA, a real CalDAV server. It is a **separate Go module** so its
dependencies can never reach the product's `go.mod` or `govulncheck`.

```
make harness                  # hermetic: unit tests for the harness itself
make harness-image            # build the node image the scenarios run
HDTP_HARNESS_LIVE=1 go test ./scenario/...   # from harness/, needs Docker
```

Some scenarios need extra images: `make harness-shaper` (traffic shaping),
`make harness-image-caldav` (the calendar scenario), `make harness-kernel` (the VM
topology). [`docs/harness-design.md`](docs/harness-design.md) explains what each
topology proves. Most of the defects listed in `PLAN.md` were found here rather than
by review, which is the argument for adding a scenario when you add a surface.

## Things that will surprise you

- **The store's SQL is generated by sqlc, and the generated code is committed.** A statement is
  written in `queries/sqlite/*.sql` and `queries/postgres/*.sql`, then `make sqlc` regenerates
  `internal/core/store/sqlitedb` and `pgdb` (sqlc is pinned in the Makefile and run with
  `go run`; nothing needs installing). `make sqlc-check`, run by the pre-push hook, fails when the
  committed code is not what the sources generate, and `TestQueriesMatchTheHandWrittenCode`
  compares every query's SQL with the code in both dialects. Query files stay pure ASCII
  (`TestQuerySourcesAreASCII` says why). The schema is `migrations/`; outside those two places
  and the tests, `TestNoHandWrittenSQLOutsideTheStore` fails the build on any statement.
- **Two storage engines.** SQLite is the default and Postgres is a first-class target;
  a query that works on one and not the other is a bug. `make check` runs Postgres too when
  `HDTP_TEST_POSTGRES_DSN` is set, and the pre-push hook always sets it.
- **`internal/` is enforced by Go's import rules**, and the harness sits inside the
  module path on purpose so it can import `internal/outbound` and talk to a node as a
  real peer would.
- **Docs are linted.** `TestDocsOnlyQuoteRealCommands` walks every `hdtp-gateway …`
  invocation in the README, this file, `docs/` and the repository's `.github/`, and fails when a
  pasteable command line names a subcommand the binary does not have. Documentation
  that quotes an invented command is worse than none. Its flag check is weaker than it
  looks — see the note in `PLAN.md`; do not rely on it to catch a wrong flag.

## The portal is an embedded React app

`web/` holds the portal SPA (React + Vite + TypeScript). Its build OUTPUT,
`web/dist/`, is **committed**, and `go:embed` compiles it into the binary — so
plain `go build` and `make dist` need no Node toolchain.

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
- Sign off your commits: `git commit -s` adds a `Signed-off-by: Your Name <you@example.com>`
  line, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
  that you wrote the contribution or otherwise have the right to submit it under this repository's
  licence. There is no CLA. A pull request with a non-merge commit that has no sign-off is not merged; the merge commit GitHub makes is not signed off and is not held to it.
- Inbound is outbound: a contribution is accepted under the Apache License 2.0
  ([`LICENSE`](LICENSE)), the terms the repository gives out.
- Tests come with the change, in the same commit. A test that has never been seen
  failing has not been shown to test anything; where it is practical, break the fix
  and watch the test fail before you submit.
- If you touch a security path — `policy.Allow`, tier resolution, envelope validation
  order, the SSRF guard, audit writes, input caps — say so explicitly
  in the description. Those get read closely.

Conduct is [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), the Contributor Covenant 2.1.

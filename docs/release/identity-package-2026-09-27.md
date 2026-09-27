# pact-identity as a package: the shared core only, consumed by version, released locally

Owner, 2026-09-27: "move pact-cloud specific parts to pact-cloud and keep shared part between cloud
and gateway to pact-identity only. repo stays private for now." And: "update code to use
pact-cloud/pact-identity package instead of one from code itself. then, create a proper release
mechanism for this package as well." Wasm delivery to the cloud: a release asset pinned by hash.

Status: **draft, awaiting approval** (standing rule 6: this moves and deletes files across repos).

## 0. What is measured today

Repos: `pact-cloud/pact-identity` (private, 96 commits, split from the umbrella 2026-09-27),
`pact-cloud/pact-gateway` (private, the node, 186 commits), the cloud at `tech-sumit/pact-cloud`,
and the umbrella `tech-sumit/pact-gateway`, which still carries both
`pact-gateway/` and `pact-identity/` in-tree and is where every change so far was made.

**Who calls what** (grep of call sites on 2026-09-27):

| Contract section | Node (Go port) | Cloud gateway Worker (Wasm, `src/pact/core.ts`) | Cloud wallet page (`src/ceremony/ceremony.js`) | `pact` CLI |
|---|---|---|---|---|
| keys: generate_key, public_key, key_info, sign, verify | yes | yes | yes | yes |
| keys: prf_salt, derive_seed, key_from_seed | — | — | yes | — |
| certificates: build_root, build_leaf, parse, validate_chain, compare_leaves, address_guard, is_normal_https, ip_is_private | yes | yes | parse, validate_chain | yes |
| certificates: root_tbs, assemble_root, leaf_tbs, assemble_leaf (two-step signing for a key held elsewhere) | — | — | yes | yes (hardware key) |
| csr: csr_new, csr_check, issue_from_csr | yes | yes | csr_check | yes |
| csr: issue_tbs_from_csr | — | — | yes | yes |
| cards | yes | yes | — | yes |
| envelopes (hpke, seal/open, follow_renewed, decide) | yes | yes | — | yes |
| vault: vault_seal, vault_open, wallet_issue | — | — | vault_seal/open | wallet_issue, check_record |

So the node and the cloud Worker share keys, certificates, CSRs, cards and envelopes. The **wallet
functions** (derived roots from a passkey PRF, two-step signing, the vault) are used only by the
cloud's browser wallet page and by the `pact` CLI; the node uses none of them.

**What in pact-identity is about pact-cloud rather than the protocol** (the audit of 2026-09-27, §3):
- `js/musts.json` / `PROOFS.md` / `js/musts.mjs`: the MUST-to-holder table names pact-cloud source and
  test files (`cloud:gateway/…`) as holders, and `gate.sh` reads `../pact-cloud` to confirm them.
- Prose naming pact-cloud internals (ceremony.js, PROOF_LABEL, check-ceremony.mjs, leave-20 etc.).
- `docs/` and comments narrating cloud decisions, and test endpoints on the product's real hosts.

## 1. Decisions (owner, 2026-09-27)

| # | Decision |
|---|---|
| D1 | **The wallet functions stay in pact-identity, shared.** They are protocol (SPEC §2.1, §9), and the node lacking them is a gap: a person on pact-cloud and a person on a self-hosted node must interoperate, so the node needs them too. Wallet support in the node is a named follow-up (§2, P6), not part of this move. |
| D2 | **The `pact` CLI stays in pact-identity** as the reference wallet tool. |
| D3 | **The umbrella stays the monorepo on top; the repos inside are independent.** `pact-gateway/` and `pact-identity/` become gitlinks to `pact-cloud/pact-gateway` and `pact-cloud/pact-identity`, as `pact-cloud/` and `pact-protocol/` already are. Work continues in the umbrella's checkouts of them, and each commits and pushes to its own repo; the umbrella commit records the pointers. |
| D4 | **The Go module is fetched over SSH, locally only.** `GOPRIVATE=github.com/pact-cloud/*`. The node's GitHub workflows cannot fetch it without a key (standing rule 4), so they are removed from the node repo and its gates run from its local hooks, as pact-identity's already do. In the umbrella a `go.work` points the node, the harness and the cloud battery at the sibling `pact-identity/go` checkout, so cross-repo work needs no release in between. |
| D5 | **The protocol stays a sibling checkout** for pact-identity's gate, with the protocol commit recorded in each release's manifest. |
| D6 | **Visibility: private for now.** The audit (§3) lists what would have to change before any publication; none of it blocks the private package. |

## 2. The work, in order (each step committed, gated and pushed before the next)

### P1 · pact-identity: shared core only, its own module path
1. Go module path `github.com/tech-sumit/pact-gateway/pact-identity` → `github.com/pact-cloud/pact-identity/go`
   (`go/go.mod`, `go/cmd/pact-identity-go/main.go`); `Cargo.toml` `repository`; a `LICENSE`
   (Apache-2.0, as `Cargo.toml` already declares).
2. Move the pact-cloud-specific material out (the audit's list):
   - the `cloud:` holder rows of `js/musts.json` become a table in pact-cloud with its own check (beside
     `check-node-claims`); pact-identity's `musts.mjs` stops walking `../pact-cloud` (it keeps the node,
     the other consumer); `PROOFS.md` is regenerated;
   - prose naming pact-cloud internals goes or names the role: `README.md:99`, `js/reproduce.sh:109`,
     `js/verify.mjs:55,87`, `CONTRACT.md:356` (re-rendered from its template), `docs/contract-one-place.md`
     (rewritten or removed);
   - the internal hosts in tests (`*.pact.contact`, `app.pact-cloud.com`) become `*.example`. Two of the
     files (`vault.rs`, `x509.rs`) are Wasm pin inputs, so this batches into the one re-pin of P2.
3. README for consumers: what the package is, the contract, how to depend on it, versioning.

### P2 · pact-identity: the release mechanism (local, no CI keys)
- **One version** for everything (the Cargo workspace, the Go module, the Wasm package), semver,
  starting at `v0.2.0`, with a `CHANGELOG.md`.
- `make release VERSION=x.y.z`, from a clean `main`:
  1. refuses a dirty tree, a branch other than main, or a version not above the last tag;
  2. runs `gate.sh`;
  3. sets the version, commits, runs `js/reproduce.sh --pin` (the container build of that commit),
     commits the manifest;
  4. tags `vX.Y.Z` and `go/vX.Y.Z` (the Go module lives in `go/`);
  5. packs the assets: `pact-identity-wasm-web-X.Y.Z.tgz`, `manifest.json` (inputs, builder digest, the
     protocol commit, sha256 of every file), `SHA256SUMS`, and `pact` CLI binaries for darwin-arm64 and
     linux-amd64/arm64;
  6. `git push` through the hooks and `gh release create vX.Y.Z` with the assets and the changelog section.
- A hermetic test runs the recipe against stubs (no push, no `gh`).
- `make verify-release VERSION=x.y.z` downloads the assets and checks them against the manifest and a
  fresh `reproduce.sh`.

### P3 · the node (`pact-cloud/pact-gateway`) consumes it by version
- `go.mod`: `require github.com/pact-cloud/pact-identity/go vX.Y.Z`, the `replace` removed, the 45
  imports on the new path; the harness module the same.
- Docker builds: the image build needs the module. With no key in CI, `make harness-image` runs
  `go mod download` on the host (SSH) and passes the module cache into the build as a named context,
  as it passes the sibling checkout today.
- `.github/workflows/` in the node repo removed (D4); `make check`, `analyze`, `sqlc-check` and
  `harness` run from its own hooks, which no longer run the identity gate (that is pact-identity's).
- `make identity-bump VERSION=…` updates `go.mod`, tidies the harness, and runs `make check`.

### P4 · the cloud consumes it by version
- `gateway/scripts/pact-identity.mjs fetch vX.Y.Z`: `gh release download` (the owner's local auth),
  verify every file against the release `manifest.json` and `SHA256SUMS`, write
  `gateway/vendor/pact-identity/` and its `VERSION`. `check-wasm.mjs` checks the vendored bytes
  against that version's manifest, not against the umbrella's `pact-identity/js`.
- The Go conformance battery: `require` the identity module by version and the node by a pinned
  commit; in the umbrella, `go.work` points both at the siblings.
- The MUST-holder table moved in P1 is checked here.
- If the Wasm bytes change (the P1 host rename does), the wallet page is re-pinned and one staging run
  proves it.

### P5 · the umbrella: gitlinks and a workspace
- `pact-gateway/` and `pact-identity/` stop being tracked trees in the umbrella and become gitlinks to
  the two repos (the trees are byte-identical today, so nothing changes on disk); the umbrella's
  history keeps everything up to that commit.
- `go.work` at the umbrella root (D4); the umbrella's own hooks and `CLAUDE.md` gate table updated to
  say which repo's hooks run what.
- `.github/workflows/pact-identity.yml` and the node's workflows leave the umbrella (they belong to the
  repos, and D4 removes them).

### P6 · follow-up (named, not in this plan): the node gains wallet support
The node creates and holds identities without the wallet functions today; interoperating with a
pact-cloud user who moves to (or from) a self-hosted node needs derived roots, the vault and two-step
signing on the node's side too. Scoped in its own plan after this one lands.

### P7 · proof
- Each repo's gate green from a **fresh clone**: pact-identity `gate.sh` (with the protocol sibling),
  the node `make check`/`analyze`/`sqlc-check`/`harness` with `GOPRIVATE` set, the cloud `make check`.
- `make verify-release VERSION=0.2.0` reproduces the Wasm byte for byte.
- One staging ship and pair run from the cloud consuming v0.2.0; production when the owner ships.

## 3. The visibility audit (2026-09-27), for later

Current tree: no secrets, no commercial logic (plans, billing, WorkOS, customers). MEDIUM items are the
pact-cloud coupling P1 removes, internal hostnames, internal process material (review and plan IDs in
tests and docs), and PROOFS.md quoting the private SPEC. History: one HIGH item (a removed extension
test that stubs the portal's API and workspace model), plus internal commit messages, two personal
emails and old Wasm blobs with local paths. Publishing later means a new repository with a cleaned
single initial commit, not a rewrite of this one.

## 4. What this plan does not do
- It does not archive the umbrella: the umbrella stays the monorepo (D3).
- It does not change the protocol, the contract or any Wasm byte except the batched prose re-pin.
- It is separate from the migration-squash and past-state plan, which comes next.

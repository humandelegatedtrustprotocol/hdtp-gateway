# Audit and cleanup plan — 2026-09-19

One generation, end to end: no dead code, no `v: 1` reader or writer, no backward-compatibility
path, every rule enforced rather than described. This file is the order of work and the record of
it. Items are taken **in order**; each is finished and verified before the next begins.

Status legend: `TODO` · `DOING` · `DONE` · `DROPPED` (with the reason).

## Diagnosis — what the sweep found

Tokens of the retired generation were counted across live source in all four repositories
(tests, `/test/`, docs and release records excluded). Three classes came back:

1. **Legitimate.** `pact-identity/js/intrude.mjs` asserts 1.x cards and envelopes are *refused* —
   those are the proof, not residue (the removal plan said to keep them). Append-only migrations
   `0014_rotation`, `0024_*`, `0027_pact20` are history and cannot be edited.
2. **Live schema and code that should be gone.** The removal plan called for a
   `0029_drop_1x` migration; `0029` is `contact_root_cert` instead, so **it was never written**.
   `accounts.prev_fingerprint`, `accounts.prev_key_sealed` and `accounts.grace_until` still
   exist, generated sqlc code still names them, and `internal/cli/backup.go:399` still nulls
   them. `accept_1x` is still a column, still queried, and still typed in the cloud.
3. **A live `v: 1` reader in the cloud.** `pact-cloud/gateway/src/envelope/envelope.ts:121` is
   `if (h.v !== 1) throw invalid(...)`. The module header still describes sealing with info
   `PACT-SEAL-v1`. Its shape codec and KEM helpers are legitimately reused by the 2.0 path and
   by `export/seal.ts`; the version check and anything only it reaches are not.

Go dead code: `staticcheck -checks=U1000,U1001 ./...` reports nothing unused in the node, so
there is no unreferenced Go to delete — the dead material is schema, generated code, and prose
that mislabels live behaviour.

## Part A — the open H items

### A1 · H20's register state is stale — `DONE`
The register says `partly closed`. The ungated half was fixed: `test:ceremony:gated` now runs in
`npm run check`, skipping loudly when no browser exists. Update the row to `closed` and say which
half was which.
*Verify:* the row reads `closed`; `npm run check` still ends on the ceremony suite.

### A2 · H19 — the shipped wasm core is stale and still contains 1.x code — `DONE`
**The first diagnosis of H19 was wrong, and this item replaces it.** H19 was filed as "the wasm
is not byte-reproducible across platforms", inferred from one observation — a no-op rebuild here
gave 636920 bytes against the pinned 639118 — and never tested. Testing it took two commands:

- `strings` on the **pinned** wasm finds `/Users/sumitagrawal/.cargo/...` 76 times. It was built on
  this machine, not on the Linux runner. The platform was never the variable.
- The pinned wasm contains the strings `X-PACT-KEY` and `compat`; a fresh build contains neither.
  The manifest was last pinned 2026-09-16; `crates/` last changed 2026-09-18, when the 1.x removal
  deleted `encode_compat`. The removal plan said "the Wasm binding dispatches generically, so no
  Wasm rebuild or re-pin is needed" — true of the dispatch, false of the bytes.

So the real defects are three, and all can be fixed here:
1. **The production core still contains the 1.x compat-card encoder.** It is the binary the
   ceremony embeds and the Worker runs.
2. **The binary embeds the builder's home directory 76 times** — a leak in a published artifact,
   and the reason bytes depend on where they were built. `--remap-path-prefix` fixes both.
3. The ports still report `spec: "2.0.0-draft"` (`api.rs:372`, `go/api.go:18`). Blocked on H19
   only by the false diagnosis; it rides this rebuild.

Steps: revert the three uncommitted "platform" explanations (`verify.mjs`, the workflow message,
`VENDORED.md`); add path remapping to `js/build.sh`; fix both version constants and the Rust test
asserting the old one; rebuild; re-pin `js/manifest.json`; vendor the five files into the cloud;
update `VENDORED.md`; re-pin the ceremony; correct H19 in the register, saying plainly that the
first diagnosis was false.
*Verify:* the fresh wasm has zero hits for `X-PACT-KEY`, `compat` and the home path; `verify.mjs`,
`check-wasm.mjs`, `check-ceremony.mjs` green; `check.mjs` 109, `parity` 270, `intrude` 115;
`cargo test`; cloud `check:fast` + 1378 tests + ceremony smoke 103.
*Unknown, and to be stated as unknown:* whether a Linux host then produces the same bytes as
macOS. Path remapping removes the known cause; it is not proof of cross-host reproducibility.

## Part B — the retired generation, removed

Ordered by dependency: the schema goes first, then the code that reads it, then the prose.

### B1 · Drop the rotation columns from `accounts` — `TODO`
New forward migration for **both** engines (`0031_drop_1x`), dropping `prev_fingerprint`,
`prev_key_sealed`, `grace_until`. Append-only, so `0014` is untouched; the Down re-creates them as
`0030` does for the relay tables, or the SQLite conformance down-migration breaks.
Then: `make sqlc`, `make sqlc-check`, fix `internal/cli/backup.go:399`, and `SPEC.md` §11.2's
column table — `TestSpecTablesMatchTheCode` reads migrations and will fail otherwise.
*Destructive:* presents the Fact-Forcing facts before running.
*Verify:* `make check` (the doclint and store conformance suites are the gate), `make sqlc-check`,
postgres conformance with the compose DSN.

### B2 · Drop `accept_1x` — `TODO`
A 1.x posture knob: whether to accept key-pinned peers, in a build that refuses them outright.
Same migration as B1 if the schema work is identical; the query in `queries/*/pact20.sql` and its
generated accessors go with it, as does the cloud's `accept_1x: 0 | 1` in `src/identity/store.ts`.
*Blocked by:* B1 landing first, so there is one migration and one regeneration.
*Verify:* as B1, plus the cloud's `check:fast` and `gen-schema.mjs --check`.

### B3 · `protocol` columns still default to 1 — `TODO`
`0027_pact20.sql` created `accounts.protocol` and `contacts.protocol` with `DEFAULT 1`, so a row
written without the field is born into a generation that no longer exists. Flip the defaults
forward. Confirm first whether anything still writes without it — `contacts/initiate.go` was fixed
earlier, so this may be schema-only.
*Verify:* the store conformance suite, which asserts engine defaults.

### B4 · The cloud's `v: 1` envelope reader — `TODO`
`src/envelope/envelope.ts`: remove the `h.v !== 1` version check and whatever only it reaches;
keep the four-member shape codec (`decodeEnvelope`/`encodeEnvelope`, used by the 2.0 path in
`identity/surface.ts`) and the KEM helpers used by `export/seal.ts`. Rewrite the module header,
which still describes info `PACT-SEAL-v1` as what this file does.
*Verify:* `check:fast`, the full test suite, `check-unwired.mjs` (deleting an allowlisted symbol
makes it "wired" and exits 1 — the allowlist entry goes in the same commit).

### B5 · Prose that mislabels live behaviour — `TODO`
Not comments about history, which are records worth keeping — these three describe what the code
does *now*, wrongly:
- `internal/outbound/client.go:32` — `Fingerprint string // X-PACT-KEY — the pinned identity`.
  Under 2.0 the pin is the **root** fingerprint; `X-PACT-KEY` is written by nobody.
- `internal/contacts/manager.go:365` — `CardKey extracts X-PACT-KEY via the real parser`.
- `internal/internalui/invite_landing.go:37,73` — **live page text** telling a person to hash a
  key "to check it matches X-PACT-KEY". A user-facing instruction in a retired vocabulary.
*Verify:* `make check`; read the rendered landing page text in its test.

## Part C — bugs introduced this session

Audit this session's own diffs rather than trusting them. In commit order: the listener chain
branch, `sealed.go`'s sealed refusals, `client20.go`'s `plaintextLegal`, `node.go`'s `state20`
N+1 and `tlsCertOf`, `leaf.go`'s `ActiveLeafKeypairsFor`, `sync.go`'s rewritten trust decision,
`record.mjs`, `parity.mjs --manifest`, and `ceremony.js`'s validity field.
Specific questions to answer, not assume:
- C1 · `syncOne` now calls `n.now()` three times in one pass; does the injected clock make that
  observable, and does `RepinContactAddress` want the same instant as the validation?
- C2 · `verifySyncedCard` falls back to `pin.SPKI` when the answer carries no chain. §6.1 says
  `get_card` always carries one. Is that fallback a path a hostile peer chooses?
- C3 · `chosenValidDays()` reads the DOM at signing. Confirm the clamp cannot be bypassed by
  removing the element (`$('rv-days')` → null → default), which is the safe direction.
- C4 · `record.mjs` shells out to `parity.mjs`; confirm a parity failure fails the record rather
  than writing a stale file.

## Part D — optimisation

### D1 · Re-measure, then decide — `TODO`
The benchmarks exist (`internal/public`, `internal/node`, `internal/core/store`). Re-run them
after Part B, since dropping columns narrows `accounts` reads. Report the delta; take nothing on
speculation. `emit_prepared_queries` stays declined — measured at 2.2× per read with a blast
radius across every query, and the protocol's own rate limits cap traffic three orders of
magnitude below what the node already serves.

## Order of execution

A1, A2, B1, B2, B3, B4, B5, C1–C4, D1. One item at a time, each verified and committed before the
next starts.

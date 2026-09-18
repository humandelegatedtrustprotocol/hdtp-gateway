# Hardening pass — 2026-09-18

A tightening pass over the node against `pact-protocol/SPEC.md` 2.0.0, looking for
impersonation, MITM, certificate forgery and replay, and for the places where a check
is weaker than the sentence that describes it. Findings are `H*`; each names the file,
the protocol sentence it fails, and the test that now holds it.

The recurring shape, again: a check that is true of what it looks at and false of what
it is cited for. Every finding below is an instance.

| # | Where | What | Severity | State |
|---|---|---|---|---|
| H1 | `SPEC.md` (whole document) | The node's own specification still describes PACT 1.0 + the 1.1 delta — key rotation, `v: 1` envelopes, relay mode, `X-PACT-KEY` cards. 27 of its 108 normative sentences govern code deleted on 2026-09-18 | high | open |
| H2 | `internal/public/listener.go:156`, `internal/public/identify.go:215` | `client_cert: required` is satisfied by **any** self-signed certificate: the single-certificate branch fills `ClientCertFingerprint` without validating anything, and the gate tests only that it is non-empty | medium | closed |
| H3 | `internal/node/node.go:318,1037,1110` | That same unvalidated fingerprint becomes the caller identity, the rate-limit bucket, the per-caller server key and the session binding — a caller mints a certificate per request and gets a fresh guest budget each time | medium | closed |
| H4 | `internal/public/identify20.go:206` | PACT §2's "both proofs present ⇒ their leaf keys MUST match" is enforced against `ClientCertSPKI`, which in the single-certificate branch is an unproven key | low | closed |
| H5 | `internal/public/sealed.go:150,164`, `spendGuestBudget` | After the envelope opened, three paths answer in plaintext. PACT §13.2: once opened, an error result MUST be sealed. `pending_approval` in the clear tells the carrier this sender is one the recipient **pins** — the correlation sealing exists to prevent | medium | closed |
| H6 | `internal/outbound/client20.go:188` | The caller attributes **any** plaintext error to the peer. Only codes that can precede opening are legitimate in the clear; a carrier can forge `permission_denied` and the owner is shown a refusal the contact never sent | medium | closed |
| H7 | `pact-cloud/gateway/src/router/profile.ts:27` | The public profile page reads `X-PACT-KEY` from the card. PACT §3: the retired properties are written by nobody and **honoured by nobody** | low | open |
| H8 | `docs/threat-model.md` | Pins described as SPKI, adversary A3 as a relay, the reviewer pointed at `internal/envelope/`'s deleted vectors — the reviewer-facing document describes the retired generation | medium | open |
| H9 | `README.md:68` | `X-PACT-KEY` presented as the identity everything is pinned to | low | open |
| H10 | `internal/**` | No benchmark exists anywhere in the node. Performance work has no baseline to move | medium | closed |
| H11 | `internal/node/outbound20.go` (was `:87-123`), `tlsCertOf` | The outbound mirror of H2: a contact pinned as 1.x that had not re-pinned was answered with the SUPERSEDED key and a self-signed certificate for it, citing Appendix C — deleted with 1.x. After H2 a conforming peer grants a lone certificate no identity, so presenting one makes the call anonymous rather than compatible | medium | closed |
| H12 | `internal/outbound/client.go:92` | "Pinned identity as server certificate" compared the presented LEAF's key against `peer.Fingerprint`, which for a 2.0 peer is the ROOT. Dead — and three tests were passing *through* it, so nothing exercised the rule a real caller meets | medium | closed |
| H13 | `docs/conformance.md:19`, error-code table | The mechanically-checked map stated a 1.x rule ("identifies callers by SPKI fingerprint") with real test names attached, and listed no row for `chain_required`, `certificate_renewed` or `seal_not_accepted`. `TestConformanceDocCitesRealTests` checks that cited names exist; it cannot check that a claim is true or that a list is complete | medium | closed |

## What the benchmarks say

Nothing in the node had ever been measured, so every performance statement about it
was an opinion. The baseline, on an M2 Max, one core:

| Path | ns/op |
|---|---|
| `sealed_call` end to end — open, tier, dispatch, seal the answer back | 884 000 |
| open a small-form envelope (every message after the first) | 379 000 |
| open a chain-form envelope (first contact, first after a renewal) | 526 000 |
| validate a chain (§14.2, two signatures and the whole profile) | 139 000 |
| seal a result back | 264 000 |
| one indexed store read (SQLite, `GetAccountByID`) | 16 000 |

**The constant factor does not need tuning, and saying so is the finding.** 884 µs is
about 1 100 sealed calls a second on one core. PACT §12 caps a contact at 60 calls an
hour and a guest at 10; a node with a hundred active contacts all at their limit is
1.7 calls a second. Three orders of magnitude of headroom, on a personal node. Chasing
the constant would be speculative work against a budget nothing is spending.

**What did need fixing was the part that grows.** `state20` walked every other account
on the node and asked for its leaves, one query each, on every inbound envelope —
134 µs at one identity, 262 µs at eight, about 18 µs per extra identity per message,
unbounded. It is two queries now: 128 µs and 155 µs, a 39% cut at eight and flat in
query count whatever the node holds. The same read also asked for the account row
twice; `ActiveLeafKeypairsFor` takes the row the caller already has.

**Measured and deliberately not taken:** sqlc emits `QueryRowContext(ctx, sql, args)`
per call, with no statement cache. The same query through a prepared statement is
3.3 µs against 7.3 — **2.2×** on every read in the node. `emit_prepared_queries: true`
would buy it, and it changes the shape of every generated file and every `New(db)`
call site. Against a budget with three orders of magnitude of headroom that is a large
blast radius for nothing, so it is written down here instead of taken.

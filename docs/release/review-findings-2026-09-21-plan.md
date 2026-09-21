# The review findings that were recorded and not fixed — plan, 2026-09-21

The owner's words: "fix Review findings which are not fixed … And other items from top, fix them".

The 2026-09-20 review of `pact-identity` (five reviewers, five slices) produced more than was fixed
that week: round 2's plan fixed the blockers (its G, H and I) and listed the rest as open. This is the
rest. Every item below was read again in the code on 2026-09-21 before it was written here.

**The authority for a disagreement between the ports is the seed** (`pact-protocol/vectors/lib`,
CONTRACT §0). Where the seed is silent — it has no address guard and no `host_of` — the stricter
reading of SPEC wins and both ports move together.

**What a change costs decides the batches.** `crates/pact-identity/**` is a build input of the pinned
Wasm core: one change there means a container re-pin, a re-vendor into `pact-cloud`, a re-pin of the
ceremony page, the cloud's gate and a staging deploy. The Go port, the CLI (`crates/pact/**`) and the
JS harness are not inputs. So: everything that does not touch the core first, in two free batches, and
then ONE batch for everything that does.

Each item: fixed on the side that is wrong, a guard seen red on the code as it was, gates, commit,
push. Status is written here as it happens.

---

## A — the CLI (`crates/pact`): free. `TODO`

| # | Finding | Fix |
|---|---|---|
| A1 | `piv.rs`: the GET RESPONSE loop has no bound; a hostile token answering `61 FF` for ever hangs the CLI and grows memory | cap the rounds and the bytes; refuse by name. The loop moves behind a small transmit seam so a hostile transport can be tested |
| A2 | `io.rs`: a new vault's file is fsynced and its DIRECTORY ENTRY is not, so `id create` can report success and leave no vault after a power loss | fsync the parent after `fill_new` and after the rename |
| A3 | secrets are zeroized in one copy of several: the passphrase inside `serde_json::Value` args, `io::core`'s `args.to_string()` (for `vault_seal` that string holds the root PKCS #8), `id_issue`'s re-check, the PIN | `Zeroizing` for the passphrase, the PIN and the serialised args |
| A4 | `id restore` writes the vault and THEN proves it opens; on failure the file stays and blocks the retry ("exists") | remove the file on a failed verify |
| A5 | `issue_on_card` passes only the issuing root to the CSR's root-key refusal; the software path passes every root in the vault | collect the vault's sibling roots (from `pkcs8` and from `cert`) on the card path too; extend the both-paths test |
| A6 | the P-256 guard on a card-held root is never reached: the test that names it passes on a different error that also contains "P-256" | a fake card reporting an Ed25519 key, asserting text only the guard produces |
| A7 | `card_proves_it_holds` borrows the certificate-SERIAL generator for its challenge: 8 random bytes where §2.2 asks 32 of the analogous proof | 32 bytes of its own |
| A8 | the live battery's CONTROL — the one call that must get through — passes on the presence of two JSON keys and never opens the envelope it is answered with. TWO drivers: `crates/pact/src/vectors.rs` and `js/live.mjs` | both open the result with the attacker's own leaf key and require `cty: application/pact-result+json`; the stub that pinned the shallow reading goes red first |

## B — the Go port adopts what the Rust core and the seed already do: free. `TODO`

Parity cases are added FIRST and seen red against the Go port as it is; `js/parity.mjs` is the guard.

| # | Finding | Fix |
|---|---|---|
| B1 | `OpenResult`: five refusals in other words than Rust's, and version/suite/kid read in another order, so one envelope gets two verdicts | Rust's strings verbatim, Rust's order |
| B2 | `Decide` decodes `enc`/`ct` with the lenient base64 reader, which cannot fail; Rust is strict and answers `does not open` | strict, same answer |
| B3 | unreadable host state — a held key's or a pin's leaf that will not parse, a tombstone's instant or leaf — is SKIPPED by Go and an ERROR in Rust and in the seed. Go's reading can quietly turn a returning-after-removal peer into a plain guest. Go also honours ANY tombstone for a root where Rust takes the first; the seed keeps one per root | Go propagates, as the seed does; first match |
| B4 | `follow_renewed`: other words for a wrong `code`, and an ABSENT chain answered as a chain of 0 | Rust's two strings; absent is not empty |
| B5 | `CSRCheck` accepts four shapes `csr.rs` refuses: an attribute with a third element, a CertificationRequest whose two parts are not SEQUENCEs, a signatureAlgorithm with trailing parameters, and the key-algorithm check in another order | mirror `csr.rs` exactly |
| B6 | `Canonical`: below 1e-4 Go writes `1e-07` where ECMAScript writes `1e-7`, and `1e-05` where it writes `0.00001`; one line replaces a string with itself | port Rust's range branch; delete the dead line; the number table from `canonical.rs`'s test |
| B7 | `now` keeps its sub-second part in Go and is whole seconds in Rust: a leaf expires up to a second earlier in one port | truncate on entry |
| B8 | 32-bit `int`: a four-octet DER length and an eight-octet pathLen are folded into `int` | fold into 64 bits, bound, then narrow |
| B9 | `FromB64url` rebuilds its table on every call on the receive path; `randomSerial` discards `rand.Read`'s error | a package table; propagate |

## C — everything that touches the pinned core, ONCE. `TODO`

Both ports move together, and the seed where it has the function. SPEC becomes **2.1.3** only if
Appendix B or a normative sentence changes (C1 adds a refused certificate, so it does).

| # | Finding | Fix |
|---|---|---|
| C1 | an `authorityKeyIdentifier` of ANY length passes the profile, and a card turns it into the identity shown to the person: a 3-byte "fingerprint" that no chain can ever satisfy | §14.1 already says a key identifier is 32 bytes: the profile refuses any other length, in Rust, Go and the seed; a refused certificate joins Appendix B and a scenario joins the intrusion suite |
| C2 | the address guard passes IPv6 literals that EMBED an IPv4 address a translator will dial: NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`. `https://[64:ff9b::7f00:1]/` is loopback on a NAT64 network. A test named "every other spelling of loopback" does not list it | recurse on the embedded address; deprecated site-local `fec0::/10` too; the test earns its name. Every COPY of the guard: Rust, Go, and whatever the node and the cloud keep of their own |
| C3 | `host_of` keeps the port, so a leaf on `:8443` can never carry the `dNSName` §14.1 permits; its comment says it carries no port | strip the port, as `address::host_of` already does; a CSR case on `:8443` |
| C4 | `card::encode` writes `FN` verbatim: a name holding CR LF injects a property the decoder reads first | refuse a control character in `FN` at encode — a name with a line break in it is not a name — in Rust, Go and the seed, and wherever the node and the cloud build a card |
| C5 | `card_decode` with no `now`: Go refuses, Rust decodes against 1970 and answers `expired: false` for every card | `now` is required in both: it is what `expired` means |
| C6 | an unauthenticated small-form envelope makes `decide` parse EVERY pinned leaf — N X.509 parses and N SHA-256s for a stranger, before freshness or replay | a pin MAY carry `leaf_fingerprint`; match on the string, parse only the match, and hold the match to its own leaf; absent, the old scan. CONTRACT says so. The node and the cloud supply it afterwards |
| C7 | `Canonical` above 2^53: Rust prints the integer's digits, the seed and Go go through a double | Rust follows the seed (RFC 8785: a number is a double) |
| C8 | `from_pkcs8`'s Ed25519 arm accepts RFC 8410-forbidden parameters; `from_spki` refuses them | require exactly the algorithm |
| C9 | `api.rs`: `chain(a, "sender_chain").ok()` reports a present-but-malformed chain as an absent one | propagate the decode error; Go the same words |
| C10 | `fingerprint_of_leaf` is public, dead, and on no dispatcher; CONTRACT §1 says the CLI "refuses" a use it merely does not expose | delete; reword |

Then, in the order `CLAUDE.md` gives: commit → `sh js/reproduce.sh --pin` → `node js/record.mjs` →
`gate.sh` → commit the manifest → vendor into `pact-cloud` (four `pkg-web` files, the manifest, the
vector fixture) → `check-wasm.mjs` → `build-ceremony.mjs --pin` → `make check wallet` → push the cloud,
the protocol, then the umbrella → staging → the served page compared byte for byte → `make e2e-staging`.

## D — "other items from top". `TODO`

Mine to do:

| # | Item | Fix |
|---|---|---|
| D1 | go-webauthn 0.18 refuses a relying party that is a single label other than `localhost`; the node learns it at the first ceremony | refuse such an `internal_host` when the config is read, by name, and document it |
| D2 | the ingress command's three accept loops were allow-listed in K's goroutine guard without being read for K's defect | read them; fix or say why not |
| D3 | `go-ntlmssp` 0.1.0 has an advisory fixed in 0.1.1 (uncalled, indirect) | bump it |
| D4 | no 0.17-format stored passkey was replayed under 0.18; the guide says it decodes | replay one |
| D5 | the staging battery skips one test by name every run | find out why, and say |
| D6 | `/healthz` counts an index-only object migration as forbidding a gradual rollout | refine |
| D7 | `pact-cloud/ARCHITECTURE.md` still describes 1.x in places | a 2.x pass |
| D8 | the contract in one place, Phases 1 and 2 (`pact-identity/docs/contract-one-place.md`) | build them: both are free |

Not mine, and said so rather than worked around: the production deploy ("later") and counsel's
answers; `pact-cloud`'s missing branch protection (a session never changes branch protection); whether
CI runs on pull requests; deleting the stale branches and the backup bundle (deletions wait for a
yes); the ideation phase.

---

## Order of execution
A, B, C (one pin), D.

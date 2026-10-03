# The review findings that were recorded and not fixed — plan, 2026-09-21

The owner's words: "fix Review findings which are not fixed … And other items from top, fix them".

The 2026-09-20 review of `hdtp-identity` (five reviewers, five slices) produced more than was fixed
that week: round 2's plan fixed the blockers (its G, H and I) and listed the rest as open. This is the
rest. Every item below was read again in the code on 2026-09-21 before it was written here.

**The authority for a disagreement between the ports is the seed** (`hdtp-spec/vectors/lib`,
CONTRACT §0). Where the seed is silent — it has no address guard and no `host_of` — the stricter
reading of SPEC wins and both ports move together.

**What a change costs decides the batches.** `crates/hdtp-identity/**` is a build input of the pinned
Wasm core: one change there means a container re-pin, a re-vendor into `batondeck`, a re-pin of the
ceremony page, the cloud's gate and a staging deploy. The Go port, the CLI (`crates/hdtp/**`) and the
JS harness are not inputs. So: everything that does not touch the core first, in two free batches, and
then ONE batch for everything that does.

Each item: fixed on the side that is wrong, a guard seen red on the code as it was, gates, commit,
push. Status is written here as it happens.

---

## A — the CLI (`crates/hdtp`): free. `DONE`

| # | Finding | Fix |
|---|---|---|
| A1 | `piv.rs`: the GET RESPONSE loop has no bound; a hostile token answering `61 FF` for ever hangs the CLI and grows memory | cap the rounds and the bytes; refuse by name. The loop moves behind a small transmit seam so a hostile transport can be tested |
| A2 | `io.rs`: a new vault's file is fsynced and its DIRECTORY ENTRY is not, so `id create` can report success and leave no vault after a power loss | fsync the parent after `fill_new` and after the rename |
| A3 | secrets are zeroized in one copy of several: the passphrase inside `serde_json::Value` args, `io::core`'s `args.to_string()` (for `vault_seal` that string holds the root PKCS #8), `id_issue`'s re-check, the PIN | `Zeroizing` for the passphrase, the PIN and the serialised args |
| A4 | `id restore` writes the vault and THEN proves it opens; on failure the file stays and blocks the retry ("exists") | remove the file on a failed verify |
| A5 | `issue_on_card` passes only the issuing root to the CSR's root-key refusal; the software path passes every root in the vault | collect the vault's sibling roots (from `pkcs8` and from `cert`) on the card path too; extend the both-paths test |
| A6 | the P-256 guard on a card-held root is never reached: the test that names it passes on a different error that also contains "P-256" | a fake card reporting an Ed25519 key, asserting text only the guard produces |
| A7 | `card_proves_it_holds` borrows the certificate-SERIAL generator for its challenge: 8 random bytes where §2.2 asks 32 of the analogous proof | 32 bytes of its own |
| A8 | the live battery's CONTROL — the one call that must get through — passes on the presence of two JSON keys and never opens the envelope it is answered with. TWO drivers: `crates/hdtp/src/vectors.rs` and `js/live.mjs` | both open the result with the attacker's own leaf key and require `cty: application/pact-result+json`; the stub that pinned the shallow reading goes red first |

**What was shown, item by item.** A1: the loop moved into a pure `gather`, and against the unbounded
loop a transport answering `61 FF` for ever was still being asked after 10,000 rounds; bounded at 64
rounds and 64 KiB, with an honest 3 KiB chained answer still gathered whole. A2: durability cannot be
shown without pulling the plug; what is shown is that the directory really is opened and synced (a
parent that is not there is an error) and that both write paths reach it. A failure is reported and the
file LEFT, since it may be the only copy of a root key. A3: `Zeroizing` for the passphrase (as typed,
as read from its file, as compared), the PIN's three copies, and both texts that cross `io::core`; a
`wipe` overwrites every string of a JSON value, which the Vault's Drop now uses instead of dropping to
Null. Only `wipe` is observable, and is tested; the rest is types. A4: red — "the unproven vault was
left at …" — then removed on a failed proof, and the same path restored to again. A5: red — a request
carrying a sibling root's key was GIVEN A LEAF on the card path — then refused as the software path
refuses it. A6: the new test goes red with the guard switched off (it then fails on the signature
instead), which the test it replaces never did. A7: 32 bytes of its own. A8: both drivers open the
control's answer — sealed to the attacker's leaf key, a result, for this call, in the window, from a
leaf that chains to the target's root at the target's address, and not a sealed refusal; the verdict for
a look-alike is `CONTROL UNOPENED` in both, held together by a test. The JS driver's OWN end-to-end
test went red the moment it opened the answer: its fake node had been answering the control with four
one-letter strings. The fake now seals a real result through the pinned core. `gate.sh` passes.

**Found on the way, and it is the core's (so it is C11):** `vault::wallet_issue` collects root keys
from `pkcs8` only, so on the SOFTWARE path a request carrying a CARD-held sibling root's key is not
refused either. A5 fixed the card path by reading every root's certificate; the core should too.

## B — the Go port adopts what the Rust core and the seed already do: free. `DONE`

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

**What was shown.** Thirty-five parity cases were written first and run against the port as it was:
twenty-five disagreed, each printed as the two answers side by side; ten already agreed and stay as
guards. With the port changed, 349 of 349 agree. The five `follow_renewed` cases that were written in
the same step as their fix were checked separately, by putting the old behaviour back: six red.

- **B1, B4** are words and order, now the core's. B4 found a third wording nobody had listed ("older
  than the pinned leaf" for the core's "older than the pin").
- **B2 was not what the plan said.** For a member that is not base64url at all, the SEED reads
  leniently, as Go did, so by wording the Rust core was the odd one. But the lenient reader also
  SKIPS a stray character beside bytes that are otherwise right; the signature covers the decoded
  bytes and still verifies; and the Go port ACCEPTED such an envelope — and `open_result` such an
  answer — where the pinned core refuses. Two spellings of one envelope, taken by one implementation
  and not the other. The rule is now that every member is base64url and nothing else: Go is strict
  here, the deployed core is not loosened, and the seed follows in C12.
- **B3** needed `Decide` to be able to say so: it returns an error for the node's own unreadable
  state, as the core returns Err and the seed throws. The NODE had to follow, and does: it refuses
  the call as it does whenever state cannot be loaded, and AUDITS `identity_state_unreadable` with
  the account and the reason, because only the owner can mend a bad row. Its test first passed for
  the wrong reason's opposite — the honest contact's pin sorted before the bad row and was matched
  first, in the core too — and now uses a stranger's small-form envelope, which reads every pin.
- **B5**: before the change the Go wallet answered `ok: true` — it would have SIGNED — for three
  malformed requests. `CSRCheck`'s reading is now `csr.rs`'s `parse` line for line, including where
  it propagates the DER reader's own words.
- **B6**: the number table is `canonical.rs`'s own ten rows plus nine; against the old code nine rows
  were red, THREE OF THEM FROM THE CORE'S OWN TABLE (`1e-7`, `0.000001`, `-0.0`). Go also follows
  the seed past 2^53 now, which is what C7 does to Rust.
- **B7**: every entry point that takes an instant truncates it; the parity case is half a second past
  a leaf's last second.
- **B8 was measured on a 32-bit target after all**: the test is cross-compiled for `linux/386` and run
  under Docker. The old reader PANICS — `slice bounds out of range [:-2147483643]` — on
  `30 84 7F FF FF FF`, six bytes of anybody's certificate, and gives the wrong refusal for three
  other lengths; the new one passes all five. A node on a 32-bit ARM board was crashable by a
  stranger. (The review had expected the panic from lengths that wrap NEGATIVE; those were refused,
  wrongly, as "not minimal". It is the length that stays positive that overflowed `at+l`.) The
  pathLen fold is by construction only: on 64 bits the two are the same number.
- **B9**: a package table; `randomSerial`'s error is propagated through the two certificate-body
  builders and their five callers.

`gate.sh`, and the node's `make check` and `make harness`, pass. PROOFS.md: 349 parity cases.

## C — everything that touches the pinned core, ONCE. `DONE` (pinned; staging deploy is the next step)

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
| C11 | `vault::wallet_issue` reads root keys from `pkcs8` only: a card-held sibling root is not among the keys a request may not carry (found while fixing A5) | read every root's certificate, as the CLI's card path now does |
| C12 | the SEED reads an envelope's members leniently (`Buffer.from(s, 'base64url')` skips what it does not know), so it accepts the second spelling B2 found; and the Rust core says `does not open` where a strict seed must say the same | a strict reader in the seed for `protected`, `enc`, `ct` and `sig`, in the core's words; an intrusion scenario for the stray character |

Then, in the order `CLAUDE.md` gives: commit → `sh js/reproduce.sh --pin` → `node js/record.mjs` →
`gate.sh` → commit the manifest → vendor into `batondeck` (four `pkg-web` files, the manifest, the
vector fixture) → `check-wasm.mjs` → `build-ceremony.mjs --pin` → `make check wallet` → push the cloud,
the protocol, then the umbrella → staging → the served page compared byte for byte → `make e2e-staging`.

**What was shown.** Both ports — and the seed — were wrong the SAME way on most of C, so parity could
not have seen it. Each port's own tests were written first and run against the code as it was: eight
at the core's boundary (`tests/findings.rs`), all red, each for its own reason — the encoded card
visibly carrying an injected `X-PACT-SEAL:none`, `wallet_issue` really ISSUING a leaf over a card-held
sibling's root key, `host_of` answering `agent.alina.example:8443`. Six intrusion scenarios REPRODUCED
against the seed as it was (four of them: the envelope was simply accepted) and are blocked now, by
the seed and by both ports: 130 scenarios, 126 blocked, 4 residual by decision. Parity: 419 cases, all
agreeing. SPEC is **2.1.3**: 49 MUSTs, the two new ones held by tests and scenarios seen red.

- **C12 grew into the rule the spec needed.** "Strict" was still several spellings: both ports
  forgave padding, whitespace and the standard alphabet in an envelope's members, consistently. And on
  the way there the Go port turned out to accept one more that the core refused — a last character
  with a spare bit set, because `encoding/base64` is lenient unless told to be `Strict()`. §13.1 now
  says a member has ONE spelling, unpadded and canonical; a wire reader in all three holds it; and a
  caller's arguments at the boundary stay forgiving, because that is a different question.
- **C5 found a divergence nobody had listed.** A MISSING instant was `parse: an instant is required`
  in every Go function that takes one, where the core and the contract say `bad_request: now is
  required`. The harness had never left `now` out. Go also leaked `encoding/json`'s own sentence for a
  member of the wrong type.
- **C4 reached two hosts.** The node's `BuildCard20` returns the writer's refusal and an account
  cannot be CREATED with a control character in its name; the cloud's `createIdentity` really did
  create an identity named `Alina\r\nX-PACT-SEAL:none` (its new test shows it) and answers
  `invalid_name` now. No identity may exist whose card cannot be written.
- **C2 reached a copy.** The cloud's status Worker keeps its own private-address predicate; it knew
  NAT64 and IPv4-mapped and not 6to4, site-local or the IPv4-compatible form.
- **C6**: shown by a pin that CANNOT be parsed and is never asked to be; red when the finder is made
  to ignore the claim. The node supplies `leaf_fingerprint` from the key it keeps beside each pin
  (the one statement that writes `leaf` writes `spki`). **The cloud does not yet**: its contact row
  keeps the key and not the fingerprint, and there is no synchronous hash on that path, so it wants
  a column. The old scan is correct there, and O(contacts). That is an open item, not a done one.
- **A flake of mine, caught before it was pushed.** The parity cases that respell an envelope were
  built from an envelope sealed with a RANDOM ephemeral key, and which respellings exist depends on
  the bytes, so the number of cases moved between runs — 420, then 421 — and PROOFS.md would have
  gone stale at random. Sealed from a fixed seed: 419, three runs. The source commit's message says
  420; the pin's commit corrects it.
- **The vectors' own note was false.** It said every certificate reproduces byte for byte. What
  Ed25519 signs does; an ECDSA signature is new each run, so `root_b`, `leaf_b`, `leaf_b_twin` and
  the P-256 envelope change their signature bytes at every regeneration. It says so now.

Protocol `ccc26d6`; umbrella source `0962ff6`, pin `91e65f4` (642,820 bytes, sha256 `5e411231…`);
cloud `8b4d5c8` (wallet page script `1d22b020…`, 947,790 bytes). `gate.sh`, the node's `check` and
`harness`, and the cloud's `make check wallet` (1,429 tests, 103/103 wallet checks) pass.

## D — "other items from top". `DONE`

Mine to do:

| # | Item | Fix |
|---|---|---|
| D1 | go-webauthn 0.18 refuses a relying party that is a single label other than `localhost`; the node learns it at the first ceremony | refuse such an `internal_host` when the config is read, by name, and document it |
| D2 | the ingress command's three accept loops were allow-listed in K's goroutine guard without being read for K's defect | read them; fix or say why not |
| D3 | `go-ntlmssp` 0.1.0 has an advisory fixed in 0.1.1 (uncalled, indirect) | bump it |
| D4 | no 0.17-format stored passkey was replayed under 0.18; the guide says it decodes | replay one |
| D5 | the staging battery skips one test by name every run | find out why, and say |
| D6 | `/healthz` counts an index-only object migration as forbidding a gradual rollout | refine |
| D7 | `batondeck/ARCHITECTURE.md` still describes 1.x in places | a 2.x pass |
| D8 | the contract in one place, Phases 1 and 2 (`hdtp-identity/docs/contract-one-place.md`) | build them: both are free |

### What each one came to

**D1.** `loadConfig` asks go-webauthn itself whether `internal_host` can be a relying party, under
the rule name `internal_host_is_a_passkey_relying_party`; SPEC.md says what the host has to be. A
second test feeds the same hosts to the config check and to the library's constructor and fails if
they ever disagree — the only reason to believe the first test asks the right question. The empty
string is the one disagreement and is excluded by name, because the config check never asks about a
host that is not set.

**D2.** Read. The ingress command's three accept loops close with the front door's own shutdown and
their handlers touch no store, so an abandoned one cannot use a closed store or audit a clean
shutdown as a failure — which is what K's guard exists to catch. The allow-list now says that
instead of "deliberate".

**D3.** `go-ntlmssp` 0.1.0 to 0.1.1. Indirect and uncalled here (`make analyze` says so).

**D4.** `testdata/passkey-webauthn-0.17.4.json` is a real record made in a worktree at the commit
before the bump; the new test signs its owner in with it under 0.18.

**D5. Answered; the skip is permanent, and the first answer was not the reason.** The battery skips
*a stale kid is answered `certificate_renewed`* because it needs `HDTP_LIVE_FORMER_KID`, the key id
of a leaf the identity USED to hold. The first answer here said a renewal could only be driven
against a deployment. That was true and beside the point: a renewal does not produce a former kid at
all. A leaf's kid goes `former` only once the leaf is superseded AND past its `not_after`
(`batondeck/gateway/src/identity/store.ts`, `retireExpiredLeaves`) — while it is merely superseded
its key is still held and still answers, which is why it is held — and the shortest validity a
wallet may issue is one day, because the lifetime is the person's choice and zero is refused. So no
journey, however it is written, can manufacture an expired leaf inside a run without a clock it does
not own. `make e2e-staging` on 2026-09-21 skipped it too, on a freshly certified identity, which is
the proof of that.

The rule is therefore proven where a clock exists, and the skip message says so rather than reading
like a missing variable: `batondeck/gateway/test/public-surface-20.test.ts` drives a renewal
against a real Durable Object, retires the old leaf at a `now` it chooses, asserts `formerKids` holds
exactly that kid, then asserts both the answer and the contact's re-seal; and `decide`'s own
`certificate_renewed` cases are proven in both ports against Appendix B. Cloud `d63fa56`.

**D6.** `/healthz`'s `identity` level is now the newest CONTRACTING migration, read from the
migration's own SQL (`batondeck/gateway/src/identity/contract.ts`): one that takes a column or a
table away, or renames, or whose author says so with a `-- contract: <why>` line, for the migration
that rewrites data incompatibly and removes nothing. 1006 adds two indexes, so the level fell from
1006 to 1005 and a build that only adds indexes may now roll out beside the one before it.
`scripts/promote.mjs --selftest` holds the Worker's copy of that judgement and the deploy script's
to the same verdict from the same text.

**D7.** About thirty-five statements in `batondeck/ARCHITECTURE.md` were false, and almost none of
them was 1.x residue: they described machinery that was designed and built differently — Workflows,
a Secrets Store, a Cedar Wasm build, one zone, in-memory rate counters, an `/events` stream,
customer hostnames, `fedramp`, a platform passkey. The disclaimer saying the tenancy, isolation,
cost and lifecycle sections "describe machinery 2.x did not move" is what kept those sections from
being read; it is gone. Three corrections touch the privacy story and were each read twice against
the code: an EXPORT is five tables with no audit chain (so `audit verify` passes on a platform
SNAPSHOT, not on an export — the same defect class this workspace keeps finding); D1 is not
"routing and billing metadata only"; and §7.1's "the platform never holds a root, sealed or
otherwise" was false of the `vaults` table, whose honest claim — cannot open it, cannot attribute
it — is the stronger one. Two comments in the cloud's own code said "Workflows" too and were fixed
in the same round.

**D8.** Phases 1 and 2 of `hdtp-identity/docs/contract-one-place.md`, both built.
`contract/contract.json` is the boundary as data: 39 methods over 34 domain types, each with the
shape of its arguments, the shape of its answer, and the error codes it may fail with.
`CONTRACT.md` is now GENERATED from it plus a prose template, and `contract/render.mjs --check`
fails when it is stale — shown red both ways, on a hand edit of the document and on a change to the
contract that was not re-rendered. `js/parity.mjs` takes its surface from the contract as well as
from the two dispatchers (a function in the file and in neither port now fails), and validates
every answer of BOTH ports against the declared shape: 838 answers, 0 off the contract, with a
failure held to the codes its method declares and 62 of 77 declared codes actually produced. That
check is the one two agreeing ports cannot pass by agreeing, and it was mutation-checked five ways
— a dropped result member, an added one, a wrong error code, a phantom method, a loosened pattern —
each red with exit 1.

Two deviations, each deliberate and written down in the proposal: the validator is not a stock one
(`js/` has no dependencies; `contract/schema.mjs` covers exactly the keywords used and `compile`
REFUSES any other, so a schema cannot state a constraint nothing holds, with
`contract/schema.test.mjs` holding each keyword to a value that must fail it), and the `params`
direction is one-way — an accepted call is a described call, but nothing proves every call the
schema admits is accepted.

It found three things. `CONTRACT.md` still called the specification 2.0.0-draft and still cited the
four `v: 1` vectors of Appendix B, which were deleted with 1.x — real residue, in the document that
is supposed to BE the boundary. And both ports accept a value the contract does not describe:
`profile_error`'s `kind`, where anything but `"root"` is read as a leaf, and `card_encode`'s
`seal`, where a non-empty value is written into the card as given. Narrowing either is a change to
`crates/hdtp-identity`, which costs a re-pin, so both are described honestly as declared-but-not-
enforced and recorded as Phase 4's first candidates, to be bundled with the next change that pays
for a re-pin.

### Found, not fixed

- `batondeck/PLAN.md` §3.1 still describes CI/CD as Workers Builds plus a Cloudflare Container
  runner. ARCHITECTURE.md now says the deploy and the battery are local and that PLAN.md is stale
  in the same way; PLAN.md itself was not rewritten here.
- ARCHITECTURE.md §12.2 claimed a test that greps the Worker bundles for the sealing primitives.
  It does not exist. The section now names the checks that do (`check-no-keys.mjs` over the git
  index, `check-placement.mjs`, the audit-coverage registry) and says plainly that what keeps a DEK
  inside an object is the object's own surface and a review rule, not a check.
- `internalui/auth`'s `passkeysFor` silently skips a stored credential that fails to decode. Seen
  while doing D4; not touched, because a change there is a change to sign-in.

Not mine, and said so rather than worked around: the production deploy ("later") and counsel's
answers; `batondeck`'s missing branch protection (a session never changes branch protection); whether
CI runs on pull requests; deleting the stale branches and the backup bundle (deletions wait for a
yes); the ideation phase.

---

## Order of execution
A, B, C (one pin), D. All four are done, and **staging now runs the 2.1.3 core**: the owner ran
`make ship-staging` and then `make e2e-staging` on 2026-09-21, which certified a fresh identity
through the real wallet ceremony and ran the whole conformance battery against it — zero failures,
one permanent skip (D5). The first of those two runs found a defect worth more than the deploy: it
reported "done" and exited 0 with its battery never run, because `make conformance` pipes into
`grep | tail` and macOS ships GNU make 3.81, which ignores the `.SHELLFLAGS` that would have made
`pipefail` apply. Three ship-path recipes were unprotected the same way (`conformance`, `wallet`,
`workers`); each now sets `pipefail` itself, and `batondeck/gateway/scripts/check-make-recipes.mjs`
runs each of them against stubs on every commit, in both directions, with the file's own property
guarded for recipes nobody has stubbed yet. Cloud `dc5bcb7`.

What is left is not mine: the production deploy, counsel's answers, `batondeck`'s branch protection, whether CI runs on
pull requests, deleting the stale branches and the backup bundle, and the ideation phase.

One open item the cloud will need: a pin MAY now carry `leaf_fingerprint` (SPEC 2.1.3 §13.1), and
the cloud's `contacts` table has no column for it. Nothing is wrong without it — a pin without the
member is read exactly as before, and only the saving is lost — so it is a migration to schedule,
not a defect to fix.

# One behaviour on every port: fixing the port-parity audit of 2026-09-29

Owner, 2026-09-29: "Make sure functionality is consistently available across platforms in pact
identity as in rust so in go and others. Also reflect it in gateway."

Status: **the owner's request is the approval** for the identity-core work (§3, P1–P4), which
changes no file layout. The consumer items (§3, P5, P6) follow the rate-limit branches, which touch
the same files. One decision is the owner's and is marked **(owner)**.

## 0. What was measured

A read-only audit (8 finders, then 2 independent verifiers per finding: one reproduced it, one
asked whether the difference was deliberate or unobservable) against identity main 95ff611 (0.4.0),
node main fb03807e and cloud main 1f21d51. The report, with file:line on both sides of every
finding, the evidence, the verifiers' corrections and the refuted list, is
`scratchpad/parity-audit/report.md`; its index is `index.tsv` beside it.

- **161 candidates: 138 confirmed, 23 refuted.** 66 high, 50 medium, 22 low.
- **By owner:** identity core 108, node 17, cloud 11, tooling 2.
- **The dominant class** is the Go JSON adapter reading a member through its Go zero value where the
  Rust core tells absent, empty, wrong-typed and present apart. CONTRACT.md §0 forbids exactly this.
- **Next classes:** IPv6 zone ids that Go's `netip` accepts and Rust refuses; keys outside the profile
  (RSA, X25519) that Rust refuses at parse and Go carries on; Go's lenient `FromB64url` on
  caller- and peer-supplied input; two KDF parsers in Go's vault; serde's own text reaching `why`;
  one admit (T5: any P-256 key opens a seal to a crafted Ed25519 SPKI under the X25519 suite).
- **What a peer can observe between a node and a hosted identity today:** N1/N2 (the node's two doors
  disagree), N4/X4/CW-03 (the node accepts small-order Ed25519 card signatures), N5/C17 (a narrower
  private-address list in the node's media fetch), N9/T22 (go-vcard refuses cards the port accepts),
  R37/CW-01 (the cloud re-encodes spare-bit envelope members), CW-02 (`why` on the wire), the
  lenient base64url findings, the zoned IPv6 endpoint, R40 (out-of-range numbers).
- **Eight new leads** raised by verifiers and not yet verified (report §4.1), three of them rated high:
  the cloud seals its outbound proof with a 60 s lifetime where the node uses 300 s; the cloud
  cannot redeem a self-hosted node's invite link; the node treats an absent `X-PACT-SEAL` as
  `required`.

## 1. Rules for every fix

1. **The contract decides; where it is silent, the stricter reading wins.** Nothing is forgiven on the
   wire. Where the seed library (`pact-protocol/vectors/lib`) is the lenient one, the seed changes in
   the same change as the ports, never after (report §2.4).
2. **Fix the class, then the instance.** Each systemic fix in §2 lands with its guard, and the guard is
   shown red on the code as it was before any instance is fixed, so the guard is what proves the
   instances.
3. **No compatibility path.** A consumer that relied on a zero-value default is changed in the same
   release train (standing rule 2).
4. **Every claim the audit found false is corrected** in the same commit as the behaviour it describes
   (report §2.6 item 10; standing rule 3).

## 2. The systemic fixes (report §2.6)

| # | Class | Guard |
|---|---|---|
| S1 | Required/empty/wrong-typed/undeclared members, read order | parity cases GENERATED from contract.json for every method: each required member absent and null; each optional string `""`; each optional member wrong-typed; one undeclared member; ordered double faults; `{}` compared whole; the Go hostile object |
| S2 | Refusals nobody compared | parity fails when a declared error code is never produced by a case in both ports, bar a committed exception list with a reason per entry |
| S3 | Go adapter zero values | one decode pattern in `go/api*.go`: pointer or RawMessage members, judged in contract read order, one checked reader for nested shapes |
| S4 | Lenient base64url | one strict exported decoder in Go for every input not produced by this process; whitespace pinned in both ports |
| S5 | Two KDF parsers | one KDF reader shared by seal and open, in each port; never truncate |
| S6 | Duplicated constants | each duplicated constant is a contract `$defs` constant read by a test in every copy's home |
| S7 | Nil and wrong-algorithm keys in Go's typed API | refuse a nil key by name; decap checks the key's algorithm against the suite (closes T5's admit) |
| S8 | Consumers reimplementing the port | a lint in the node's and the cloud's gates for the named reimplementations |
| S9 | The node's two doors | one decision function for the TLS door and the sealed door; `why` as a fact, not prose; contract methods for what hosts duplicate (`media_holds_private_key`, `limits_buckets`, `refresh_check`) |

## 3. The work, in order

- **P1 (identity).** S1, S2, S6 first, each shown red. Then S3, S4, S5, S7 and every identity finding the
  report lists (108), grouped by the report's clusters, one commit per cluster, both ports and the seed
  together. The report's corrected claims and **Direction** lines override the finders' proposed fixes.
- **P2 (identity).** Every false comment and record the report lists (S10), in the commits of P1 that
  change the behaviour they describe, or in one last commit if the behaviour did not change.
- **P3 (verification).** Every confirmed identity finding is re-run against the new branch by a verifier
  that did not write the fix; a finding is closed only when its reproduction now answers the same on
  every port.
- **P4 (release).** pact-identity 0.5.0 (a minor bump: stricter reading changes answers). `gate.sh`, the
  pin, `make release`, `publish`, `verify-release`.
- **P5 (node), after the two-layer node PR lands.** Bump to 0.5.0; S8's node lint; S9 (one decision for
  both doors); N4 (card signatures through the port); N5 (the port's private-address list); N9 (the
  port's card decode); every node finding; the new leads that verify.
- **P6 (cloud), after the two-layer cloud PR lands.** Bump to 0.5.0; S8's cloud lint; R37/CW-01 (the
  core sees the members as received); CW-02; R38 (`media_holds_private_key` from the core); every cloud
  finding; the new leads that verify (the 60 s proof lifetime; redeeming a node's invite).

**(owner) N1:** SPEC §5.3 (SPEC.md:307) reads a removal tombstone only when there is no pin; the node's
TLS door also applies it to a pinned root. The plan makes the TLS door follow the SPEC and the seed.
If the owner wants a pinned root to be refused after a removal too, that is a SPEC change instead.

**(owner) A contact with no card on file** (found closing lead 4, 2026-09-30). SPEC §3 reads a card
with no `X-PACT-SEAL` line as `none`, and the node now does too (`contacts.SealOf`, the core's
`DecodeCard` reading). A contact that arrived in an export has no card at all: contacts.csv carries
neither a card nor a policy (§9.2), so the host does not know whether the contact accepts envelopes
until a card of theirs reaches it. The SPEC does not say what a host assumes then. The node seals to
such a contact, as it always did; PACT Cloud seals to every contact whatever its card says. If the
owner wants something else (plaintext, or asking the contact's plain `tools/list` whether it lists
`sealed_call`), that is a SPEC sentence first.

## 4. What this plan does not do

- It does not change the wire format or any SPEC MUST, except where §2.4 of the report shows the seed
  and a MUST disagree; each such case is named in its commit.
- It does not touch the rate-limit work in flight.

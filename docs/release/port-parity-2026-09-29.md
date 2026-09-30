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
  - **Cards already stored, read by the stricter core.** The node's intake (`contacts.ValidateInbound`)
    and its seal policy (`contacts.SealOf`) both read a card with the core's `DecodeCard`, today
    0.4.1's. A card 0.4.1 accepted at intake and 0.5.0 refuses stays on file after the node's bump
    (P5), and `SealOf` then answers an error for it: that contact cannot be written to (`node.PeerOf`
    refuses it) until a card of theirs that reads arrives. So the node's bump carries a migration
    check: `SealOf`, under 0.5.0, over every stored card (every account, every status), run before
    the bump is pushed, naming each card it refuses with its contact and the reason. The owner then
    refreshes each of those contacts (the on-demand refresh of ONE contact, standing rule 5) or
    re-adds it from a new card, and the bump ships when the list is empty or the owner has accepted
    what is left on it.
- **P5 (node), after the two-layer node PR lands.** Bump to 0.5.0; S8's node lint; S9 (one decision for
  both doors); N4 (card signatures through the port); N5 (the port's private-address list); N9 (the
  port's card decode); every node finding; the new leads that verify.
- **P6 (cloud), after the two-layer cloud PR lands.** Bump to 0.5.0; S8's cloud lint; R37/CW-01 (the
  core sees the members as received); CW-02; R38 (`media_holds_private_key` from the core); every cloud
  finding; the new leads that verify (the 60 s proof lifetime; redeeming a node's invite).
  - **A cloud lead to fix: PACT Cloud seals to every contact, whatever its card says.** Its outbound
    client (`gateway/src/outbound/client.ts`) seals every call and reads no `X-PACT-SEAL`, so a
    contact whose card says `none`, or has no such line (PACT §3: "Absent = none"), is sent an
    envelope it said it would not take — PACT §13.4's "senders MUST NOT seal", broken. The node
    reads the policy off the card on file (`contacts.SealOf`, fix/parity-leads). The cloud's fix is
    the same reading, from the core's `DecodeCard`, on every outbound door, with a test that a `none`
    card and a card with no line are called in plaintext.

**(owner) N1:** SPEC §5.3 (SPEC.md:307) reads a removal tombstone only when there is no pin; the node's
TLS door also applies it to a pinned root. The plan makes the TLS door follow the SPEC and the seed.
If the owner wants a pinned root to be refused after a removal too, that is a SPEC change instead.

**(owner) A contact with no card on file** (found closing lead 4, 2026-09-30). SPEC §3 reads a card
with no `X-PACT-SEAL` line as `none`, and the node now does too (`contacts.SealOf`, the core's
`DecodeCard` reading). Two paths write a contact with no card at all: an import, whose contacts.csv
carries neither a card nor a policy (§9.2), and the owner approving a root that returned after a
removal (`contacts.DecideAddress`), which re-adds it from the pending address — a leaf and an
endpoint, no card. Either way the host does not know whether the contact accepts envelopes until a
card of theirs reaches it. The SPEC does not say what a host assumes then. The node seals to such a
contact, as it always did; PACT Cloud seals to every contact whatever its card says, which breaks
§13.4 for a card that says `none` and is a cloud lead to fix (P6). If the owner wants something else
(plaintext, or asking the contact's plain `tools/list` whether it lists `sealed_call`), that is a
SPEC sentence first.

## 4. What this plan does not do

- It does not change the wire format or any SPEC MUST, except where §2.4 of the report shows the seed
  and a MUST disagree; each such case is named in its commit.
- It does not touch the rate-limit work in flight.

## 5. What the node's leads leave for pact-identity (fix/parity-leads, 2026-09-30)

- **Lead 2: `pending_approval` names no signer.** A `pending_out` contact's sealed call is decided
  `pending_approval`, and Decide's result is `{code}` alone, in both ports and in the contract
  (`$defs` Decision, `additionalProperties: false`), at 0.4.1 and at the port-parity branch
  (d029713). The signature has verified by then (Go's `Decide` at 0.4.1: in the small form after
  `VerifyDetached` under the pinned leaf, in the full form after `ValidateChain` and `VerifyDetached`
  under the chain's leaf), but the node is not told under which leaf. The node now reads it itself
  (`public.signerOf`: the peeked chain's leaf, or the pinned leaf the small form names, matched as
  `pinHolding` matches it, and only for a `pending_out` pin) and seals the refusal to it, and the
  budget's refusal on that path too, and charges the call to the root that signed, which pays as a
  proven pending contact: the guest bucket of that root at its address, no guest total, its source
  known (`TestAPendingContactsSealedCallIsAnsweredPendingApproval`; `node.chargeOf`, held by
  `TestASealedContactIsNotBudgetedAsAGuest`'s "a pending_out root at the guest charge"). It still
  cannot apply the pin effects Decide returns beside it (a pending contact's newer leaf, or its new address under
  `auto`, is dropped: `decideEnvelope` returns before `apply`). What the node
  needs: `pending_approval` carrying `root`, `endpoint`, `leaf` and `form`, as `ok` does, in Go's
  `pendingApproval`, Rust's `envelope/decide.rs` (both places) and the contract. Reading the signer
  from that answer instead of `signerOf` is a simplification, not a change in what the node answers;
  applying the effects it carries IS a change (the pin follows), and is a commit of its own with
  its own test.

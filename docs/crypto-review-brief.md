# Cryptographic review brief

This document exists to make an independent review of PACT's envelope and certificate
cryptography cheap and pointed. It states the construction, says what is already tested, and
— most usefully — lists the questions we actually want answered, including the ones we
suspect are problems.

Nothing here has been reviewed by anyone outside the project. That is the gap this document
is meant to close, not one it closes by itself.

The normative text is `pact-protocol/SPEC.md` (§2, §13, §14 and Appendix B). This page is a
reading order for it, not a second copy; where the two disagree, the specification is right
and this page has a bug.

## The construction

**Identity.** A person *is* a self-signed X.509 **root**, named by
`"sha256:" + base64url(SHA-256(SPKI))` over its DER SubjectPublicKeyInfo. The root's key
lives in the person's wallet and never on a host. A host holds a **leaf** the root signed,
naming the one address it may be served at; the chain is always `[leaf, root]`, and a lone
certificate names nobody (PACT §2, §14.2). Two algorithms: ECDSA P-256 and Ed25519.

**A root derived from a passkey** (PACT §2.1). `seed = HKDF-SHA256(ikm = prf, salt = "",
info = "pact/root/1", L = 32)` where `prf` is the WebAuthn PRF extension's output for the
fixed salt `SHA-256("pact/vault/1")`; the seed is an Ed25519 private key. Two more `info`
strings derive the key and the address of the wallet's own encrypted record.

**Sealed envelope** (PACT §13.1). Four base64url wire members:

```
protected   canonical-JSON (RFC 8785) header bytes — also the HPKE AAD
enc         HPKE encapsulated key, of exactly the suite's Npk
ct          HPKE ciphertext
sig         detached signature by the sender's LEAF key over protected ‖ enc ‖ ct
```

The header carries `v` (= 2), `suite`, `kid` (the recipient leaf key's fingerprint),
`msg_id`, `ts`, `exp`, `cty`. There is no sender in it: the sender's chain — or, once the
receiver holds that leaf, the leaf's fingerprint — travels inside the ciphertext.

**Suites**, fixed by the recipient's leaf key type and refused if they disagree with it:

| Suite | KEM | KDF | AEAD |
|---|---|---|---|
| `PACT-SEAL-P256` | DHKEM(P-256, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM |
| `PACT-SEAL-X25519` | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20-Poly1305 |

HPKE **Base mode** (RFC 9180), `info = "PACT-SEAL-v2"`, AAD = the raw `protected` bytes.
Signatures: ECDSA is ASN.1 DER over SHA-256; Ed25519 is pure RFC 8032.

**Key conversion.** An Ed25519 leaf key is converted to X25519 for the KEM — RFC 7748 §4.1
for the public half, RFC 8032 §5.1.5 for the private scalar. An all-zero DH output is
refused on both sides.

**Open order** (PACT §13.3), which is load-bearing and deliberately not the obvious order:
decode → `v` and `suite` → resolve `kid` to a leaf key held for the identity at that path
(a superseded one answers `certificate_renewed`) → suite matches the key → **HPKE open** →
plaintext shape → the sender's `chain` validated (§14.2) or its `leaf` found among the pins
→ **verify signature** under that leaf key → tier → freshness (`now < exp`,
`|now − ts| ≤ 300 s`) → `msg_id` idempotency. Decryption precedes signature verification
because HPKE Base needs no sender key, and because the sender's certificates ride *inside*
the ciphertext so that a carrier sees which key a message is for and never who sent it.

## Questions we want answered

Ordered by how much we suspect them.

**Q1 — One leaf key, three jobs.** A leaf's keypair is the TLS key (client and server), the
HPKE recipient key and the envelope signing key. For P-256 that is ECDSA signing plus
DHKEM(P-256) on the same key; for Ed25519 it is EdDSA signing plus X25519 ECDH on the same
scalar. It is documented and accepted (PACT §13.5), bounded by the rule that a leaf key
signs exactly four structures, each distinguishable by its first bytes, and by a leaf's
lifetime. **Is the reuse exploitable, or only inelegant?**

**Q2 — Signature input is plain concatenation.** `sig` covers `protected ‖ enc ‖ ct` with
no length prefixes and no domain separation tag. What fixes the boundaries is that `enc`
MUST be exactly the suite's `Npk` and that the AEAD has already succeeded with `protected`
as AAD. **Is that reasoning complete?** We would prefer to be told to add length prefixes
than to be right by accident.

**Q3 — Decrypt-before-verify.** The order above opens the HPKE ciphertext before any
signature is checked, so unauthenticated attacker-chosen ciphertext reaches the AEAD, and
then an attacker-chosen certificate chain reaches the X.509 parser. **Does anything about
this ordering leak, or create an oracle?**

**Q4 — The blocked-sender path.** A blocked contact is deliberately handled exactly as a
stranger is, and an unknown leaf, a blocked one and a bad signature all answer
`chain_required`, so that acceptance cannot distinguish "blocked" from "never met". **Is
that indistinguishability real, including in timing?**

**Q5 — Replay and freshness.** Idempotency is per envelope `msg_id`, recorded until
`min(exp, ts + 300 s)`. **Is a record that expires with the skew window enough, and is 30
days a defensible cap on `exp − ts` when nothing later than 300 seconds is accepted?**

**Q6 — Ed25519 → X25519 conversion.** Standard, but conversion plus signing on the same key
is exactly the combination the literature warns about. **Is our use within what is
considered safe?**

**Q7 — The derived root.** One PRF output, three HKDF `info` strings, a fixed PRF salt
(PACT §2.1 argues why it cannot be per-credential). **Is the separation between the root
key, the store key and the store address sound, and does anything about a fixed salt weaken
it?**

**Q8 — The certificate profile.** §14.1 pins a narrow DER profile and §14.2 the six rules a
chain is validated by, of which rule 5 binds a leaf to the address it was dialled at. **Is there a chain a
conforming validator accepts that it should not?**

## What is already checked, so you need not

- **Test vectors**: PACT Appendix B — `v: 2` envelopes, certificates, chain cases and the
  derivation. The Rust core, its Wasm build and an independently written Go port open and
  reproduce them: the core
  (`pact-identity/crates/pact-identity/tests/vectors.rs`), the Wasm
  (`pact-identity/js/check.mjs`) and the port (`pact-identity/go/vectors_test.go`: `TestV2Envelopes`, `TestChainCases`,
  `TestCertificatesReproduce`, `TestDerivationVectors`).
- **Agreement between the ports**: `pact-identity/js/parity.mjs` drives the same cases
  through all of them and compares whole answers; `pact-identity/PROOFS.md` is generated
  from it and lists every case and every normative sentence with what holds it.
- **Refusals**: `pact-identity/js/intrude.mjs` is a battery of hostile inputs — stale info
  strings, moved `enc`/`ct` boundaries, small-order points, malformed DER — run against the
  Wasm core and the Go port, verdict by verdict.
- **This node's decision**: `internal/public/decide_test.go` and `sealed_test.go`
  (`TestV2SmallFormUnknownBlockedAndBadSignatureAreOneAnswer`,
  `TestV2StaleKidIsAnsweredWithTheCurrentChain`, `TestSealedReplayReturnsRecordedResult`).
- **Parsers**: four fuzz targets (`make fuzz`), including the sealed payload.
- Full claim-to-test map in [threat-model.md](threat-model.md).

## Explicitly not asking about

These are decided, documented in PACT §13.5, and not defects: no forward secrecy at the
envelope layer (HPKE Base to a leaf key that lives at most 398 days); metadata visible to a
carrier (`kid`, timing, sizes); post-quantum deferred. A review is welcome to argue the
decisions were wrong — but they were decisions.

## Reproducing

```
cd pact-identity && cargo test                       # the Rust core against Appendix B
cd pact-identity/go && make test                     # the Go port against the same vectors
cd pact-identity && node js/check.mjs && node js/parity.mjs && node js/intrude.mjs
cd pact-gateway && make check                        # this node: fmt, vet, race tests
```

The construction lives in `pact-identity/crates/pact-identity/src/envelope.rs` and its Go
port `pact-identity/go/envelope.go`; this node's use of it is
`internal/public/decide.go` and `internal/public/sealed.go`. Those are the review.

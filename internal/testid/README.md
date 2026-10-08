# internal/testid

Builds real HDTP identities for tests: a person's root, the leaf it issues to a host, and the card
that carries that leaf. A card is a certificate (HDTP §3), so a test that needs a peer's card needs
a root, a host key, a leaf naming the endpoint and a signature over the chain; this package is the
one place that builds them, so a suite does not grow six slightly different wallets. Every
certificate comes from `hdtp-identity`'s own builders (`BuildRoot`, `BuildLeaf`, `EncodeCard`), the
same ones the wallet and the node use.

Callers are test files in `internal/cli` (17 files), `internal/contacts`, `internal/identity`,
`internal/integrationtest`, `internal/internalui` (and `ownermcp`), `internal/node`,
`internal/outbound`, `internal/portable`, `internal/public`, `internal/tunnel` and
`internal/storecheck`'s tests. No non-test file imports it. It is a leaf (rank 0 in
`internal/integrationtest/layering_test.go`). Every function takes a `testing.TB`, not a
`*testing.T`, so a fuzz target can build a real identity for its seed corpus
(`internal/cli/offer_fuzz_test.go`).

## What it holds

- Identities (`testid.go`): `NewWallet(t, cn, alg...)` is a person's root (Ed25519 by default, or
  `"p256"`); `Wallet.Issue(t, endpoint, alg...)` is a host with a leaf for one endpoint (P-256 by
  default, valid from an hour ago for a year); `Wallet.IssueOver(t, endpoint, spki)` issues over a
  key the caller already holds; `Host.Card(fn, seal)` renders its card; `Card(t, fn, endpoint,
  seal)` returns a whole identity and its card; `CardFor(t, fn, endpoint)` is the shortest form (no
  seal policy). `DER(t, s)` decodes base64url by the identity core's rule; `Root(t, der)` parses a
  root certificate.
- Damaged cards (`withcert.go`, `pasted.go`): `WithoutCert` removes the `X-HDTP-CERT` property and
  its continuation lines; `WithCert` replaces its value with one on a single line; `Pasted` damages
  the folding the way a chat did on 2026-10-05 (continuations lose their leading space but the
  third, a blank line after the first and the fourth, LF line ends).
- Card signatures (`cardsig.go`, `forge.go`): `SignedCardSigs` returns a `CardSigs` with the honest
  `card_sig` and the spellings a strict reader must refuse (`padded`, `the standard alphabet`,
  `spare low bits in the last character`, `a line break inside`, `R of small order`);
  `SmallOrderR` signs with a zero nonce so R is the identity point; `SpareBits` spells the same
  bytes a second way.
- TLS files (`tlsfiles.go`): `ServerFiles` writes a self-signed ECDSA P-256 server certificate and
  key as PEM into a directory, valid for 24 hours: ordinary web TLS for the internal surface, not
  an HDTP certificate.

## What it refuses, and how

It has no error returns: every function ends the test with `t.Fatal`/`t.Fatalf` when it cannot
build what it was asked for (a key or certificate that fails, a card with no `X-HDTP-CERT` for
`WithoutCert`/`Pasted` (for `WithCert`: none followed by `X-HDTP-SEAL`), a `Pasted` card whose certificate folds over too few lines, a
base64url string that does not read in `DER`, a signature that `crypto/ed25519` does not verify in
`SmallOrderR`). `Host.Card` panics if `EncodeCard` refuses the name.

## Invariants

- Nothing is a shape invented for tests: leaves and roots come from `hdtp-identity`.
- `SignedCardSigs` keeps drawing keys (up to 64) until the signature's standard-alphabet spelling
  differs from its base64url one, so the "standard alphabet" case is always a different string.
- `SmallOrderR`'s signature is checked to verify under `crypto/ed25519` before it is returned; it
  is a signature `crypto/ed25519` accepts and the identity core's `VerifyDetached` refuses.
- `WithoutCert` fails unless the card actually lost its certificate.

## Held by

The package has no tests of its own; its users hold it. `internal/cli/offer_cardsig_test.go`
(`TestAnInvitesCardSigIsReadStrictly`) and `internal/node/refresh_cardsig_test.go` use
`SignedCardSigs`; `internal/cli/request_cut_test.go` (`TestACutCardSaysWhatToDo`) uses
`WithCert`/`WithoutCert`; `internal/cli/request_pasted_test.go` (`TestAPastedCardIsAsked`) and
`internal/contacts/pasted_test.go` use `Pasted`; `internal/cli/healthcheck_test.go` uses
`ServerFiles`.

## What it does not do

It is not enforced to be test-only: the layering test ranks it but does not forbid a production
import. It does not produce identities with a particular seed; keys are random on every call.
A leaf is issued valid from an hour before the call for a year, so a test of expiry has to build its own leaf.

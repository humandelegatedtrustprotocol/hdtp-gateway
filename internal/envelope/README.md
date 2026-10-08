# internal/envelope

The node's name for two things about a sealed envelope: the shape of its protected header and the one error every malformed envelope maps to. The envelope itself, the sealing and opening, and the order of the checks are hdtp-identity's (`Envelope`, `Decide`) and HDTP §13 in `hdtp-spec`; `SPEC.md` §4 says the same. The only callers are in `internal/public` (`decide.go`, `identify.go`, `sealed.go`), which unmarshal `Header` after `Decide` has decided and wrap `ErrInvalid` around every refusal it raises itself. The package imports nothing from the node.

## What it holds

- `ErrInvalid`: the error `envelope_invalid` (HDTP §12). `public.Code` maps any error that wraps it to that wire code.
- `Header`: the protected header's members as Go fields (`cty`, `exp`, `kid`, `msg_id`, `suite`, `ts`, `v`), in the header's key order.

## What it refuses, and how

Nothing: there is no function here. `ErrInvalid` is the value the callers return; `internal/public` wraps it with a reason (for example `fmt.Errorf("%w: recipient state unavailable", envelope.ErrInvalid)`) and `public.Code` reports the wire code `envelope_invalid`. Whether an envelope is well-formed is decided by hdtp-identity before the node reads a `Header`.

## Invariants

- `internal/envelope` ranks 0 in the layering table: it may import no other package of the node.
- `Header` has no encoder and no decoder logic of its own, only `json` tags; there is no second parser of the envelope here to disagree with the library's.

## Held by

- `internal/integrationtest/layering_test.go`, `TestImportsPointDownTheLayers`: holds the package at rank 0.
- `internal/public/decide_test.go`, `TestFirstContactMustRedeemOrRequest`, asserts that an error built on `ErrInvalid` is reported by `public.Code` as `envelope_invalid`; `internal/public/guesttotal_test.go` asserts the `envelope_invalid` answer on the wire for a chain whose signature is not its leaf's and for a client certificate that is not the envelope's leaf. The package has no tests of its own.

## What it does not do

- It does not parse, seal, open, verify or replay-check an envelope. Reading `Header` from `protected` is not a decision that the header is valid.
- It does not carry the retired generation's crypto or a lenient decoder; both are gone (see the comment in `envelope.go`).

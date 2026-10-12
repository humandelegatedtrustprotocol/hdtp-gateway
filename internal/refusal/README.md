# internal/refusal

The one reading of a failure that the owner's doors answer with: the owner MCP's
`{"code","detail"}` (`internal/internalui/ownermcp`, `refused`) and the message the portal's send
and add-contact forms show (`internal/internalui`, `pageError`). Rank 4 in
`internal/integrationtest/layering_test.go`: it reads the domain's refusals (`contacts`,
`messaging`, `integrations`, `store`), and both doors, which may not import each other, import it.

## What it holds

- `Of(err)` returns the code and the detail:
  - a `BadRequest` in the chain is `bad_request` with its sentence alone;
  - `contacts.ErrUnknownContact` and `integrations.ErrUnknownRequest` are `not_found`;
  - `contacts.ErrWrongState` and `integrations.ErrRequestClosed` are `conflict`;
  - `contacts.ErrBadRequest` and `messaging.ErrBadRequest` are `bad_request`;
  - `contacts.ErrContactCap` is `payment_required`;
  - `messaging.ErrTooLarge` and `messaging.ErrQuota` are `too_large`.

  Each of these keeps the error's own text, which the node wrote. `store.ErrNotFound` is `not_found`
  with `NotFoundDetail`. Anything else is `internal` with `InternalDetail`. No text the node did not
  write is in a detail.
- `BadRequest(sentence, cause)` marks a sentence the node wrote about a caller's arguments. The
  cause, a dial or a peer's answer, is behind it for `Error()` and in no detail. `Sentence(err)`
  reads the sentence back.

Producers: `internal/cli/contactinit.go` (add_contact's refusals) and `internal/cli/ownerextra.go`
(set_exposure's tool that is not offered).

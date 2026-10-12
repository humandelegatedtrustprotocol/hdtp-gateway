# internal/refusal

The one reading of a failure that the owner's doors answer with: the owner MCP's
`{"code","detail"}` (`internal/internalui/ownermcp`, `refused`) and the message every portal page
shows for a failed action (`internal/internalui`, `pageError` and `pageStatus`). Rank 4 in
`internal/integrationtest/layering_test.go`: it reads the domain's refusals, and both doors, which
may not import each other, import it.

## What it holds

- `Of(err)` returns the code and the detail, reading through `%w` and `errors.Join`:
  - a `BadRequest` in the chain is `bad_request`, and an `Unavailable` `unavailable`, each with its
    sentence alone;
  - an `Undelivered` is `unavailable` with "recorded, not delivered: <why>";
  - an install refusal the identity package worded (`identity.Worded`) is `bad_request` with its
    text;
  - a `messaging.FetchRefusal` is its code with its sentence;
  - `contacts.ErrUnknownContact`, `integrations.ErrUnknownRequest` and `identity.ErrNoCertificate`
    are `not_found`;
  - `contacts.ErrWrongState`, `integrations.ErrRequestClosed`, `integrations.ErrNoCatalog`,
    `integrations.ErrNotConnected` and `identity.ErrSlugTaken` are `conflict`;
  - `contacts.ErrBadRequest`, `messaging.ErrBadRequest`, `integrations.ErrExposureRefused`,
    `identity.ErrDisplayName`, `identity.ErrUnknownAlgorithm` and `auth.ErrLabelRequired` are
    `bad_request`;
  - `contacts.ErrContactCap` is `payment_required`;
  - `messaging.ErrTooLarge` and `messaging.ErrQuota` are `too_large`.

  Each of these keeps the error's own text, which the node wrote. `store.ErrNotFound` is
  `not_found` with `NotFoundDetail`. Anything else is `internal` with `InternalDetail`.
- `BadRequest(sentence, cause)` marks a sentence the node wrote about a caller's arguments, and
  `Unavailable(sentence, cause)` one about something it could not reach; `Of` answers either with its
  sentence alone. `Undelivered(why, cause)` marks a message recorded and not
  delivered; `Why(err)` reads the reason back. A cause (a dial, a peer's answer) is in `Error()` and
  in no detail.

Producers: `internal/cli/contactinit.go` (add_contact's refusals), `internal/cli/ownerextra.go`
(set_exposure's tool that is not offered), `internal/services/settings` (pairing and unpairing),
`internal/internalui` (its own validators and the web wallet's), and `internal/node/send.go`
(delivery failures).

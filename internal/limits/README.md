# internal/limits

The node's side of HDTP §12's call budgets: a client of the limits sidecar (`cmd/hdtp-limitd`,
Rust), asked over a kept-open unix socket for every decision. The node never decides a budget
itself: it opens the envelope, works out what the call is charged to, and asks; the sidecar holds
the numbers (its configuration file) and the counters, one set for every account and every node
process on the host. The package is a leaf (rank 0 in `internal/integrationtest/layering_test.go`).

Callers: `internal/node` builds charges (`chargeOf`, `outbound.go`) and calls `Decide`, `Admit`,
`Advertise` and `Probe`; `internal/public` embeds `Advertised` in the card's `limits` (`bounds.go`);
`internal/cli` constructs the client with `limits.New(cfg.LimitsSocketPath())` in `serve` and in
`doctor`. The sidecar for tests is started by [`limitstest`](limitstest/README.md).

## What it holds

- `Client` (`New(path)`): one sidecar over one kept-open connection, safe for concurrent use
  (requests are serialised on the connection). Nothing is dialled until the first exchange.
- Charges, built by constructor: `ContactIn`, `GuestIn`, `ContactOut`, `StrangerOut`, `GuestTotal`,
  `Integration`, `PendingIn`. `Charge.Kind` names the charge for an audit row. The zero `Charge` is
  not a charge.
- `Client.Decide` charges one call to every charge in the list, all or none, and returns a
  `Decision`; its `known` argument is a source the sidecar remembers for the identity.
- `Client.Admit` asks, before the open, whether a sealed call from a source may go on to the open;
  it spends nothing.
- `Client.Advertise` returns the `Advertised` call budgets for an identity allowed a number of
  contacts, for `get_card`; it spends nothing.
- `Client.Rules` returns the sidecar's `Rules`, read once and kept; `Client.Probe` reads them again
  and refreshes the kept copy. It spends nothing and proves the sidecar
  answers: `/healthz` and `serve`'s banner ask it through `node.LimitsAnswer`, `doctor` and
  `healthcheck --limits` (the sidecar container's own healthcheck) call it directly.
- `Decision`: `Allowed`, `RetryAfter`, `RefusedBy`, `Countable`.
- `DefaultTimeout`, `Client.Timeout`, `Client.Path`.

The wire is one JSON object a line in each direction.

## What it refuses, and how

- `ErrUnavailable` is the sidecar not answering. It is returned (wrapped) when the socket cannot be
  dialled, an exchange times out or fails twice, the answer does not read, the answer names a wait
  below zero or above 86 400 seconds, the answer to `rules` carries no rules or to `card` no limits,
  or the sidecar answers an `error` (a request this client should not have sent).
- `Decide` with no charges, or with a zero `Charge`, returns a plain error that is not
  `ErrUnavailable`: it is the caller's mistake and nothing is sent.
- A refusal is not an error: `Decision.Allowed` is false, `RefusedBy` names the bucket, and
  `RetryAfter` is the whole seconds until it holds a call. `Countable` is false for a refusal no
  wait ends (the pending cap); then `RetryAfter` is zero.
- The node turns an `ErrUnavailable` into a sealed `unavailable` answer and audits
  `limits_unavailable`; a refusal becomes `rate_limited` with the bucket, or `unavailable` when not
  countable (`internal/node/node.go`, `refusalOf`).

## Invariants

- One exchange is tried at most twice: a connection that fails mid-exchange is dropped and the
  request is sent once more on a fresh one, so a restarted sidecar costs a reconnect, not a refusal.
- The deadline of an exchange is `Timeout` (`DefaultTimeout` when zero) or the context's deadline,
  whichever is sooner; the dial counts against it.
- A charge is sent with exactly the members its kind has (`Charge` holds them as a map built by the
  constructor).
- The client holds no copy of any number: `Rules` and `Advertised` are read from the sidecar.

## Held by

`client_test.go`, which runs the real sidecar through `limitstest`:
`TestEveryKindOfChargeIsLetThroughFreshAndRefusedOnceSpentAndAnotherIdentityIsUntouched`,
`TestTheRulesAreTheSidecarsAndAreReadOnce`,
`TestASidecarThatIsDownIsUnavailableAndOneThatComesBackIsReconnectedTo`,
`TestAZeroChargeIsTheCallersMistakeNotTheSidecars`,
`TestTheGuestTotalIsSpentWithTheGuestAndAskedBeforeTheOpenWithoutSpending`,
`TestASidecarRefusesARulesFileItCannotEnforce`, `TestTheCardIsTheRulesAndTheCratesAggregate` and
`TestTheShippedConfigurationIsEnforceableAndCarriesTheOwnersNumbers`. The tests need the sidecar
binary: `make limitd`, or `HDTP_LIMITD=<path>`.

## What it does not do

- It does not decide, cache or default a budget. A sidecar that does not answer is an error here and
  the node answers every sealed call `unavailable` until it does.
- It does not start the sidecar; the operator runs `cmd/hdtp-limitd` beside the node
  (`serve` prints `limits: ... answering` or `limits: NOT ANSWERING` in its banner).
- `Rules` is not refreshed by itself: the kept copy changes only on `Probe`.

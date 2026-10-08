# services/retention

The node's slow background sweeper (SPEC §7.9, §9.1, §11.1): one ticker that applies every policy about age. `internal/cli/serve.go` runs `Run` in its joined background group. It calls `internal/messaging` (`Sweeper`, `BlobDir`), `internal/contacts` (`Owner.ExpireRequests`), the store, and the callbacks `serve` hands it (leaf retirement, trail archive, cache invalidation, leadership). The owner's windows come from `Windows`, implemented by `*settings.Service` (`internal/services/settings`).

## What it holds

- `Run(ctx, settings, st, cfg, auditFn, stderr, retireLeaves, archiveTrail, invalidate, leading)`: blocks until `ctx` ends, runs one pass at startup and one every `SweepInterval`, and never returns while a pass is running.
- `SweepInterval` = 1 hour. `ChangeLogKept` = 7 days.
- `Windows`: `RequestExpiryFor(ctx, accountID)` and `StorageFor(ctx, accountID)` (quota, retention window).

A pass does, in this order (`retention.go:78-130`):

1. Returns at once when `leading` is non-nil and reports false (one process on the store sweeps).
2. Calls `retireLeaves(ctx)`, then `archiveTrail(ctx)`, each only when non-nil.
3. Store-wide: deletes idempotency records and owner sessions past their own expiry, and change-log rows older than `ChangeLogKept`.
4. For each account: expires pending contact requests (theirs and ours) older than `settings.RequestExpiryFor`, writing one `contact_expire` audit row per removed contact (`account:<id> contact:<fingerprint> status:<status>`), then, only when the account's retention window is positive, runs `messaging.Sweeper.Sweep`, which deletes messages older than the window, empty threads, and blobs no retained message references.

## What it refuses, and how

Nothing is refused. A failed step is printed to stderr as `retention: <what>: <error>` and the pass continues, except that a failed account listing ends the pass without a message. Nothing is printed once `ctx` has ended: a pass cut short by shutdown has not failed.

## Invariants

- Unlimited retention is the default: a zero or negative window deletes no message.
- `Run` joins its work: it returns only after a running pass has finished, so `serve` can wait for it before closing the store.
- Only the leading process sweeps, when a `leading` function is given; nil means always.
- Active contacts are never expired by this pass; only pending ones (`pending_in`, `pending_out`).

## Held by

`retention_test.go`:

- `TestTheSweeperReturnsOnlyWhenItsPassHasAndAStoppingNodeIsNotAFailure`: `Run` does not return while the leaf-retirement callback is blocked, returns after it is released, and prints nothing to stderr.
- `TestTheSweepExpiresRequestsNobodyAnswered`: with the default 30 days and one account set to 7, a 31-day-old `pending_in`, a 31-day-old `pending_out` and an 8-day-old `pending_in` on the 7-day account are removed; an 8-day-old `pending_in` on the default account and a 90-day-old `active` contact stay; three `contact_expire` rows are audited and `invalidate` is called for the expired outgoing one.
- `TestTheRetentionPassRunsOnlyWhileItLeads`: the startup pass runs when `leading` is true and not when false.

No test here covers the message sweep itself; `internal/messaging/retention_test.go` holds `Sweeper`.

## What it does not do

It does not decide the windows (settings does), does not retire leaves or archive trails itself (it calls the functions it is given), and does not run between ticks: a window set while the node is up takes effect at the next hourly pass. It does not delete contacts that are active, and with no window set it deletes no message.

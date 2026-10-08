# services/auditsink

The node's single writer of the audit chain as the surfaces see it. Every surface takes a three-argument function `(action, resource, outcome)`; this package turns the hash-chain writer (`internal/core/audit.Writer` over `store.AuditAppender`) into one such function per actor kind, and mirrors each written row to stderr. `internal/cli/serve.go` builds the sink and hands its functions to the rest of the node; `internal/cli/portablecmd.go` also uses it.

## What it holds

- `New(ctx, st, stderr)` returns a `*Sink`. Rows are written with the values of `ctx` but not its cancellation (`context.WithoutCancel`), so the rows written while the node stops are not lost. The stderr mirror is on unless the environment variable `HDTP_LOG` is `off` (read in `New`).
- `Sink` methods, each returning `func(action, resource, outcome string)` unless noted:
  - `Owner()`: actor kind `owner`, for the portal and the owner MCP.
  - `System()`: actor kind `system`, for the node's own lifecycle.
  - `Kinded()`: `func(kind, action, resource, outcome)`; a kind outside `owner|token|contact|guest|cli|system` is written as `system`.
  - `SystemChecked()`: as `System`, but returns the append error, for the sweep that archives a departed identity's trail and must not continue past a row that was not written (SPEC §3.11).
- The account of a row is recovered from the resource string: a leading `account:<id>` (ended by a space or tab) fills the account column (`accountFromResource`). A resource without that prefix is written with an empty account.

## What it refuses, and how

It does not refuse. A failed append is printed to stderr as `audit: <action> <resource> <outcome>: <error>` and the call returns normally (`SystemChecked` returns the error instead). The mirror line is `<kind> <action> [<resource>] <outcome>`.

## Invariants

- Only the six actor kinds the store's schema accepts reach the store; anything else becomes `system` so the append is not rejected and the chain has no hole. Held by `TestAuditActorKindIsAlwaysWritable`.
- All four functions append through one writer, so the chain has one tail (comment on `SystemChecked`).
- The mirror carries the audit row and nothing else; the comment on `New` states that the chain records a setting's key and never its value, and content-addressed references rather than bodies. This is a property of what callers put in `resource`, not something this package checks.

## Held by

`auditsink_test.go`, `TestAuditActorKindIsAlwaysWritable`: writes six valid kinds and six invalid ones through `Kinded`, then asserts no stderr line starts with `audit:`, 12 rows exist, every stored kind is in the allowed set, and all six invalid ones were stored as `system`. It does not test `HDTP_LOG=off`, `SystemChecked`, `Owner`, or the account recovery.

## What it does not do

It does not decide what is audited, validate `resource` contents, or read the chain (the CLI's audit command and the portal do). It does not retry a failed append.

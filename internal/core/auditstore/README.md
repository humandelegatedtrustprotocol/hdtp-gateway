# internal/core/auditstore

The join between the audit package and the store. `core/audit` describes the slice of the store it needs
in its own terms (`audit.Store`, `audit.DepartedStore`, with `audit.Row` and `audit.Anchor`) so that it
imports no node package; `core/store` holds `store.AuditRow` and `store.AuditAnchorRow`. `Adapter` is the
one place that converts between them. It sits at rank 2 in the layer table
(`internal/integrationtest/layering_test.go`), above `core/store` and `core/audit`.

Callers: `internal/cli/auditcmd.go` builds an `Adapter` for the offline `audit` commands (`verify`,
`archive`, `repair`) and `internal/cli/serve.go` builds one for the `audit.Departed` sweep. The write path
does not go through it: `core/store.AuditAppender` adapts the store to `audit.Sink` for the writer.

## What it holds

- `Backing`: what an `Adapter` reads, namely `store.AuditStore` plus `GetAccountByID`.
- `Adapter{St Backing}`: a store seen as `audit.Store` and `audit.DepartedStore`. Its methods, one for each
  of the two interfaces' methods and each a conversion over the store's method of the same name:
  `ListAuditEvents`, `AuditAnchor`, `SetAuditAnchor`, `DeleteAuditEventsThrough`, `ListDueLeaves`,
  `ArchiveRows` (which calls the store's `ArchiveAuditRows`, sending only each row's `Seq` and `Hash`) and
  `AccountExists`.

## What it refuses, and how

It adds no refusal of its own. Every error from the store is returned unchanged, including the store's
refusal to move the anchor backward and the audit trail's refusal, in the engine, to delete a row that is
not archived. `AccountExists` is the one method that interprets an error: `store.ErrNotFound` from
`GetAccountByID` becomes `false` with a nil error, and any other error is returned.

## Invariants

- **The conversion copies every field.** `audit.Row` and `store.AuditRow` have the same twelve fields, and
  `rowsOf` copies each; `audit.Anchor` and `store.AuditAnchorRow` have the same four, copied by
  `AuditAnchor` and `SetAuditAnchor`. A field added to one and not the other is a compile error only on the
  side that constructs it, so the adapter has no guard of its own beyond its callers' tests.
- **It is on the only path that deletes from the chain.** `TestOnlyTheArchiveDeletesFromTheChain` fails if
  anything outside `core/store`, this adapter and the archive code in `core/audit` calls
  `DeleteAuditEventsThrough`, `ArchiveRows` or `ArchiveAuditRows`, and fails if this list goes stale.
- **It holds no state and decides nothing**: `Adapter` is a struct of one field, and no method keeps
  anything between calls.

## Held by

No test in this directory. The adapter is exercised by the tests that use it: `departed_test.go` in
`internal/core/audit` builds an `auditstore.Adapter` over a real store to run `Departed` and the chain
checks, and `internal/cli/audit_test.go` runs the
`audit` commands, which go through it. Two guards in `internal/integrationtest/wholechain_test.go` name it
as the join: `TestOnlyWhatVerifiesTheChainReadsAllOfIt` allows `auditstore.go` to read the whole chain, and
`TestOnlyTheArchiveDeletesFromTheChain` allows it, with `audit/archive.go` and `audit/departed.go`, to call
the store's deletes on the chain.

## What it does not do

- It does not write the chain. Sealing and appending are `audit.Writer` over `store.AuditAppender`.
- It does not verify, archive or repair anything; it only lets `audit` do so over a store.
- It does not guard against a mismatch between the two row shapes beyond the compiler: see Invariants.

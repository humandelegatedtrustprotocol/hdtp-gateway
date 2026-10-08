# internal/core/audit

The audit chain (SPEC §11.4 to §11.6): an append-only sequence of rows, each bound to the one before it by
a SHA-256 hash, so that an edit, a reordering or a removal shows up as the first row that no longer links
or hashes. This package seals rows, verifies chains, and moves rows out of the live table into archive
files without breaking the chain. It does not touch a database: it describes the slice of the store it
needs in its own terms (`Sink`, `Store`, `DepartedStore`), and `core/auditstore.Adapter` and
`core/store.AuditAppender` are the joins. It is rank 0 in the layer table
(`internal/integrationtest/layering_test.go`): it imports no package of the node; the store imports it.

Callers: `internal/services/auditsink` (the node's writer, for every row `serve` appends), `internal/cli`
(`serve.go` builds the `Departed` sweep; `auditcmd.go` is `audit verify`, `audit archive`, `audit repair`
and `audit erase-archive`), and `core/store` and `core/auditstore`, which carry rows to and from it.

## What it holds

**A row and its hash (`audit.go`).**

- `Event` is one row: `Seq`, `TS`, `AccountID`, `ActorKind`, `ActorID`, `Action`, `Resource`, `Outcome`,
  `RequestID`, `Details`, `PrevHash`, `Hash`, and `Erased`, which marks a row whose content was erased from
  an identity's archive (never set on a live row, never hashed).
- The hash is `SHA-256(prev_hash ‖ canonical row)`: `prev_hash` as its raw 32 bytes, then the canonical JSON
  of the hashed fields (`account_id`, `action`, `actor_id`, `actor_kind`, `details`, `outcome`,
  `request_id`, `resource`, `seq`, `ts` and `v`, the `ChainVersion`), keys sorted, no whitespace, no HTML
  escaping. Hashes are stored as lowercase hex. The first row's `prev_hash` is `GenesisHash`, 64 zeros
  (32 zero bytes).
- `HashEvent` computes a hash; `Next` fills `PrevHash` and `Hash` for the event that follows a given hash
  and is the single sealing path for new rows.
- `Verify` re-walks a segment anchored at its own first row; `VerifyFrom` takes the anchor explicitly and is
  the one to use. Both return the index of the first broken row, or -1. An `Erased` row must link
  (`PrevHash` equals the previous hash) and its hash is taken as written, since nothing is left to recompute
  it from.
- `ExportJSONL` and `ImportJSONL` write and read archives, one JSON object per line.

**The writer (`writer.go`).** `Writer.Append` seals one event and hands it to a `Sink`, whose
`AppendAuditEvent` reads the chain's head and inserts the row in one transaction, so any number of writers,
in one process or several on one store, extend one chain. A `Writer` keeps no head between appends.

**Archiving the head (`archive.go`).** Pruning is the one operation that can quietly destroy what the log
is for, so it is not "export then delete":

- `Archive(ctx, st, dir, throughSeq, archived, now)` writes the live rows through `throughSeq` to a JSONL file
  in `dir`, reads the file back and verifies it, records the new `Anchor`, and only then deletes the rows
  (`Store.DeleteAuditEventsThrough`). It first runs `Repair`, and refuses a chain that does not verify.
- `Anchor` is the last seq archived and its hash, the file it went to, and when. `Repair` finishes a run
  that recorded the anchor and died before deleting. `VerifyChain` checks the live rows against the anchor
  (genesis when nothing was archived); `VerifyWithArchives` walks the head archive files, the identity
  archives and the live rows as one chain from genesis.
- `Store`, `Row`, `Events`, `ArchiveResult` and `ErrArchiveInterrupted` complete it.

**Archiving an identity's trail (`departed.go`).** A leave erases an identity everywhere but the chain.
After the node's `audit_archive_after` (default `core.DefaultAuditArchiveAfter`), `Departed.Run` moves every
row that names the identity, by its account column or its resource (`Names`), to
`<data_dir>/audit-archive/<account-id>-<from>-<to>.jsonl`, mode 0600. Those rows come from the middle of
the chain and keep the `prev_hash` they were sealed with, so `Merge` puts archived rows back in their places
by seq and everything is verified as one chain. The move is ordered: write, sync, rename and read back the
file; append one `audit_archive` row (`ArchiveAction`) naming the segment and not the identity; then one
transaction deletes the listed rows (`DepartedStore.ArchiveRows`). `ArchiveFiles` and `ReadArchives` read the
archives; `Erase` replaces an archive's rows with their seq, `prev_hash` and `hash` alone, for when law
requires the rows themselves to go, and `audit erase-archive` records it with `EraseAction`.
`Segment` reports what one identity's archive moved.

## What it refuses, and how

- `HashEvent` fails when `PrevHash` is not 32 bytes of hex.
- `VerifyFrom` fails at the first row whose `PrevHash` does not extend the one before ("the chain is
  broken, reordered, or its head was removed") or whose recomputed hash differs.
- `VerifyChain` returns `ErrArchiveInterrupted` (wrapped) when live rows the anchor claims to have archived
  are still present, naming the state instead of reporting an honest chain as broken; and it fails when the
  live table is empty while the anchor claims history, which archiving never produces.
- `Archive` refuses a chain that does not verify, refuses to archive the entire chain (at least one row
  stays so the anchor has something to anchor), and fails if the archive file already exists
  (`O_EXCL`).
- `Repair` refuses, with `ErrArchiveInterrupted`, when the anchor names no archive file or the file cannot be
  confirmed to hold the rows (it re-derives every hash from each row's content), because then the live
  rows are the only copy.
- `Merge` fails when a seq is held twice with different content.
- `Departed.Run` stops at the first identity it cannot archive; the rows stay where they are for the next
  sweep. It never moves rows out of a chain that does not verify, and skips an account that is still on the
  node.
- `Erase` refuses an archive with no rows and an erased file name that already exists.

## Invariants

- **Genesis is 32 zero bytes, hashes are lowercase hex and deterministic, and the canonical JSON is stable
  and unescaped** (`TestGenesisIsZeroBytes`, `TestHashDeterministicAndLowercaseHex`,
  `TestCanonicalJSONIsStableAndUnescaped`).
- **A one-byte edit, a reordering and a deletion are detected; so is a truncated head**, which a self-anchored
  `Verify` cannot see and `VerifyFrom` can (`TestVerifyDetectsSingleByteTamper`,
  `TestVerifyDetectsReorderAndDeletion`, `TestHeadTruncationIsDetected`).
- **An archive and the live rows verify as one chain** (`TestReanchoredArchivePlusLiveVerifiesAsOneChain`,
  `TestHeadAndIdentityArchivesVerifyTogether`).
- **Archiving leaves the database holding verifiable rows at every step**: an interrupted run is repairable
  and is not reported as tampering, and a repair refuses to delete rows whose archive is missing or was
  rewritten (`TestInterruptedArchiveIsRepairableNotTampered`, `TestRepairRefusesWithoutItsArchiveFile`,
  `TestRepairRefusesAnArchiveWhoseRowsWereRewritten`).
- **An identity's trail moves only after its period, a crash loses and duplicates no row, one
  `audit_archive` row is written per segment, a tampered archive is detected, and an erased archive still
  links the chain** (`TestTheTrailOfAnIdentityThatLeftMovesOnlyAfterItsPeriod`,
  `TestACrashMidArchiveLosesAndDuplicatesNothing`, `TestOneAuditArchiveRowPerSegment`,
  `TestATamperedArchiveIsDetected`, `TestAnErasedArchiveStillLinksTheChain`).
- **A writer after an archive extends the chain**: the rows about to go are never the tail, so a restarted
  writer reading its next seq from the tail cannot reuse an archived seq (`TestAWriterAfterAnArchiveExtendsTheChain`).
- **One chain, however many writers**: a fresh `Writer` picks up the persistent chain, and writers in
  several processes extend one (`TestWriterExtendsPersistentChainAcrossRestart`,
  `TestWritersInSeveralProcessesExtendOneChain`).
- **Only the archive deletes from the chain, and only what verifies reads all of it.** The store's two
  deletes are reached only through `archive.go`, `departed.go` and the `auditstore` adapter, and the
  whole-chain read `ListAuditEvents` only by those, `auditstore` and `internal/cli/auditcmd.go`
  (`TestOnlyTheArchiveDeletesFromTheChain`, `TestOnlyWhatVerifiesTheChainReadsAllOfIt`, in
  `internal/integrationtest/wholechain_test.go`).
- **Only `Writer.Append` seals a row**: it is the one caller of `Next` in production code (`audit_test.go` calls it too). The writer is built in
  two places, `auditsink.New` for the node and `audit erase-archive` for its own row.

## Held by

`audit_test.go`, `writer_test.go` and `departed_test.go` in this directory; `internal/cli/audit_test.go` for
the `audit` commands over a real data dir (`TestAuditExportThenVerifyGreen`,
`TestAuditTamperedExportDetected`, `TestAuditRefusedWhileNodeRunning`,
`TestAuditArchivePrunesAndKeepsTheChainVerifiable`, `TestAuditAnchorCannotBeUsedToHideAWipe`,
`TestVerifyFailsWhenTheArchiveIsGone`, `TestEraseArchiveRefusals`); and the two guards in
`internal/integrationtest/wholechain_test.go`. The tests in
`writer_test.go` and `departed_test.go` are in package `audit_test` and run against a real SQLite store; Postgres is added to
them only when `HDTP_TEST_POSTGRES_DSN` is set, which the pre-push hook does. The engine-side
guard that the trail cannot be updated or pruned outside an archive is `TestTheTriggerStillRefusesAnyOtherDeletion`
in `departed_test.go`.

## What it does not do

- It does not decide what is audited, by whom or about what. The caller supplies the account, actor,
  action, resource, outcome and request id; `Details` is opaque and an empty one is stored as `{}`. The
  node's sink (`internal/services/auditsink`) derives the account from the resource.
- It does not redact. `core.Redact` is what a caller uses to strip credential shapes from text that came
  from elsewhere before it is written down; its comment gives the reason, that the chain cannot be
  unwritten.
- It does not sign. Hashes are unkeyed SHA-256: the chain shows that the rows and files it is given link and
  hash, relative to an anchor, and nothing about who wrote them. The anchor is a plain row, and
  `VerifyChain` refuses the states an honest run never produces (an empty live table behind a non-empty
  anchor, rows the anchor already claims) instead of trusting it.
- It does not enforce append-only itself. The database does, by triggers that refuse an UPDATE of
  `audit_events` and a DELETE unless the anchor covers the row or `audit_archive_rows` lists its seq and
  hash; this package is how a row comes to be covered.
- It does not run on a schedule. `Departed.Run` is called by `serve`'s retention sweep, and `Archive`,
  `Repair` and `Erase` by the `audit` commands, which take the data-dir lock and refuse to run while a
  `serve` holds it.

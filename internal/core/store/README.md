# internal/core/store

The persistence boundary of the node (SPEC §11). One `Store` interface, two implementations: `SQLite`
(the default, one file, WAL mode) and `Postgres` (pgx, many node processes on many hosts sharing one
database). Everything the node keeps passes through it: owners and their credentials, accounts and their
leaf ledger, contacts and pins, threads and messages, integrations, settings, the audit chain and its
archive anchor, the change log, leases and owner presence.

It sits at rank 1 of the layer table in `internal/integrationtest/layering_test.go`: above the two
generated packages `core/store/sqlitedb` and `core/store/pgdb` (rank 0, as are `core`, `core/audit` and
`core/policy`), below the services and surfaces. Its callers are
the domain services and the surfaces (`identity`, `contacts`, `messaging`, `integrations`, `portable`,
`public`, `node`, `internalui` and its `ownermcp` and `auth` packages, `services/*`, `storecheck`) and
the wiring in `cli`. A consumer takes the role interface it needs (`store.ContactStore`,
`store.AuditStore`, ...) rather than the whole `Store`. It imports `core/audit`, for `AuditAppender`
only.

All database access is through sqlc and this package (standing rule 1). Every statement lives in
`queries/sqlite/*.sql` and `queries/postgres/*.sql`; `make sqlc` generates `core/store/sqlitedb` and
`core/store/pgdb` from them and from `migrations/{sqlite,postgres}`; this package calls the generated
methods and maps their rows to the domain types below. No SQL is written by hand in it.

## What it holds

**The contract (`store.go`).** `Store` is the union of twelve role interfaces and declares nothing of its
own:

- `Lifecycle`: `Migrate`, `SchemaCurrent`, `Close`, `Atomically`, `Scrub`.
- `OwnerStore`: owners, credentials, sessions, owner-MCP tokens, memberships.
- `AccountStore`: accounts, their keys, the root and leaf ledger, a move campaign's fan-out
  (`MoveFanout`), the wallet-request state of a pending leaf, and the deletes of an identity that
  leaves.
- `InviteStore`: invites, found by the hash of their token.
- `SettingStore`: the owner-set configuration rows.
- `ContactStore`: contacts and the pin, the guarded status moves, tombstones, former endpoints, pending
  addresses, the import writes.
- `MessageStore`: threads, messages, blobs, read markers, idempotency records, retention deletes.
- `IntegrationStore`: integrations, immutable catalog and exposure versions, sealed credentials,
  pending agent-answered requests.
- `AuditStore`: the append, the reads, the anchor, and the two deletes the chain permits.
- `ChangeStore`: the change log every process sharing a store reads and writes, and `WatchChanges`.
- `PresenceStore`: when the owner's agent last asked.
- `LeaseStore`: named leases that hand background work to one node process at a time.

The row types are `Owner`, `Account`, `Leaf`, `Tombstone`, `FormerEndpoint`, `PendingAddress`,
`MoveFanout`, `Setting`, `Membership`, `Credential`, `Contact`, `ExpiredContact`, `Invite`, `Thread`,
`Blob`, `Message`, `Integration`, `Catalog`, `Exposure`, `PendingRequest`, `Token`, `AuditRow`,
`AuditAnchorRow`, `AuditArchiveRow`, `AuditPage`, `Change` and `CreateAccountParams`. `Message.Deadline`
and `Account.HasRoot` are the two methods on them. `DefaultMessageExpiry` and
`UndatedIdempotencyWindow` are the two durations the contract names.

**The engines.** `OpenSQLite(path)` and `OpenPostgres(ctx, dsn)` return `*SQLite` and `*Postgres`. Each is
written as a set of paired files, one per area of the schema (`contacts_sqlite.go` and
`contacts_postgres.go`, and likewise `identity_state`, `integrations`, `invites`, `messaging`, `leave`,
`retention`, `core_settings`, `audit_anchor`, `contacts_accept`), with the engine's own lifecycle in
`sqlite.go` and `postgres.go`. Two files hold what is shared so that it is written once:

- `params.go` turns a domain value into a statement's parameters (the defaults a new row takes, the
  encodings, the NULLs), for both engines. The Postgres adapter converts the result with a struct
  conversion (`pgdb.InsertContactParams(p)`), which the compiler refuses the day the two generated
  types drift. Five generated types differ between the engines and stay per engine: the two audit-page
  parameter types, `DeleteCredentialIfNotLast`'s, and `Setting`'s and `PutSetting`'s (`secret` is boolean
  on Postgres and an integer on SQLite).
- `rows.go` turns a generated row into the domain type. `sqlc.yaml`'s overrides give the Postgres rows
  the same Go shape as the SQLite ones, so the Postgres adapter converts its row to a `sqlitedb` type
  and calls the same mapper.

`audit_append.go` holds `AuditAppender` (a store seen as `audit.Sink`) and `appendAudit`, the body of
`AppendAuditEvent` inside the transaction that holds the chain's head. `changes.go`, `leases.go` and
`presence.go` hold both engines' implementations of those three roles.

**How each engine is built, migrated and opened.**

| | SQLite | Postgres |
|---|---|---|
| Driver | `modernc.org/sqlite` through `database/sql` | `pgx/v5` through `pgxpool` |
| Open | one DSN: foreign keys on, WAL, 5000 ms busy timeout, `synchronous(FULL)`, `secure_delete(1)`, `_txlock=immediate`; a pool of 4 connections (`sqliteConns`). The type's comment gives the measurement behind each setting | `pgxpool.New(dsn)` |
| Migrate | goose over the embedded `migrations.SQLite`, no lock | goose over `migrations.Postgres` through `stdlib.OpenDBFromPool`, under a session-level advisory lock, so processes starting together take turns |
| `SchemaCurrent` | shared `schemaCurrent`: an error naming both versions when the schema is behind or ahead of the binary's | same |
| `Atomically` | `BeginTx`, which takes the write lock at BEGIN; a nested call runs in the same transaction | `pool.Begin`; a nested call runs in the same transaction |
| `LockAccount` | nothing to do: every transaction already runs alone | `SELECT ... FOR UPDATE` on the account row |
| `AppendAuditEvent` | relies on the write lock taken at BEGIN | takes an advisory lock (`LockAuditChain`) before reading the head |
| `AppendChange` | one writer at a time | takes an advisory lock (`LockChanges`), inserts, then sends a notification at commit |
| `WatchChanges` | returns at once: the poll is the only way to learn of another process's change | holds a connection `LISTEN`ing, calls `wake` on each notification |
| `Scrub` | checkpoints and truncates the WAL, and fails if the log is not empty afterwards | does nothing (SPEC §3.9 names the divergence) |
| Sharing | many processes on one host, one data dir | many processes on many hosts |

`MigrateDown` exists on both engines for the conformance suite's up/down/up check; it is not on the
interface.

## What it refuses, and how

- **`ErrNotFound`** is `sql.ErrNoRows`, the same value, on either engine (pgx's `ErrNoRows` wraps it, so
  `errors.Is(err, store.ErrNotFound)` holds on both). The reads that return one row (`GetOwner`, `GetAccountByID`, `GetContact`, `GetThread`, `GetBlob` and the other single-row gets)
  return it when the row is not there. Four shapes are not that: `AuditAnchor` returns the zero
  `AuditAnchorRow` with a nil error when nothing was archived; `GetAccountSealedKey` returns nil bytes with
  a nil error for an account with no key; `OwnerPresenceSeenAt` returns 0 when the agent never asked; and
  `TakeLease` returns false, not an error, when another holder has the lease. A caller
  outside this package asks the question with it, because `database/sql` may not be imported outside the
  store.
- Some writes report an absent row with `ErrNotFound` (or an error wrapping it): `DeleteOwner`,
  `RemoveMembership`, `ClearContactHandshake`, `SetMessageStatus`, `SetMessageAttempt`, `RevokeInvite`,
  `UpdateAccountSeal`, and the integration writes. Others report it with a plain error that does not wrap
  it (`"store: account %s not found"`, `"store: leaf %s not found"`, `"store: contact not found"`,
  `"store: token missing or already revoked"`): `SetAccountRoot`, `SetAccountLeafKey`,
  `SetAccountHostPolicy`, `ClearAccountKey`, `UpdateLeaf`, `SetLeafMoved`, `SetLeafRequest`,
  `RepinContactAddress`, `SetContactChainSentKid`, `RevokeToken`, and the contact writes that end in
  `contactChanged` (`UpdateContactStatus`, `UpdateContactPermissions`, `UpdateContactTrust`,
  `DeleteContact`, `SetContactPetname`, `UpdateContactCard`, `SetContactAccepted`). A caller cannot
  `errors.Is` those.
- A guarded write that finds its guard false reports it as `false` with a nil error and changes nothing:
  `MoveContactStatus`, `DeleteContactInStatus`, `RedeemOverPendingContact`, `MarkContactRequested`,
  `TakeBackContactRequest`, `ConsumeInviteUse`, `AnswerPendingRequest`, `ConsumeLeafRequest`,
  `RemoveCredentialIfNotLast` (false means that was the last credential of its kind), `TakeLease`,
  `ImportContactPin`.
- `SetAccountKey` refuses an account that is missing or already keyed; the first key binds once.
- `SetAuditAnchor` refuses to move `ArchivedThroughSeq` backward.
- `ImportContact` and `ImportContactPin` refuse a contact with no `HandshakeDueAt`.
- `ArchiveAuditRows` rolls back unless every named row (by seq and hash) was in the chain.
- `Scrub` on SQLite refuses to run inside a transaction, and errors if the WAL is not empty afterwards.
- The schema's own constraints (unique slug, one pending leaf per account by the index
  `leaves_one_pending`, `(account, contact, direction, msg_id)` unique, the `CHECK` lists on status
  columns, the foreign keys) refuse as the engine does. Those errors come from the driver, passed through
  or wrapped with `%w`, and are not translated to a store error.

## Invariants

- **No hand-written SQL outside the store, and none inside it.** `TestNoHandWrittenSQLOutsideTheStore`
  (`internal/integrationtest/nohandsql_test.go`) fails on `database/sql`, a driver or goose imported
  outside `internal/core/store`, on any string literal that is a SQL statement, and on a statement-running
  call inside the store's hand-written files. `TestQueriesMatchTheHandWrittenCode`
  (`internal/integrationtest/queriesdrift_test.go`) reads every query in `queries/` against the generated
  code in both dialects; `make sqlc-check` fails when the committed generated code differs from its
  sources.
- **The two engines are held to one behaviour** by `conformance.Run` (see `store/conformance`), run by
  `TestSQLiteConformance` and `TestPostgresConformance`.
- **`Store` is its roles and nothing else** (`TestStoreIsOnlyItsRoles`).
- **Every statement has a plan** that does not scan a growing table without a listed reason
  (`TestEveryQueryHasAPlan`; its Postgres half runs when `HDTP_TEST_POSTGRES_DSN` is set). It proves an
  index exists for each statement; `scale_test.go` measures what each is worth at scale.
- **Query sources are ASCII** (`TestQuerySourcesAreASCII`): sqlc v1.30.0 slices statements by a rune offset
  over bytes, and one non-ASCII character corrupts every statement after it.
- **No dollar-quoted literal in argument-bearing SQL** (`TestArgumentBearingSQLHasNoDollarQuotedLiterals`).
- **A contact's leaf and its fingerprint are written together** by every statement that writes `leaf`, in
  both dialects (`TestEveryStatementThatWritesALeafWritesItsFingerprint`).
- **The audit trail is append-only and prunable only once archived.** The engine enforces it: an update
  trigger refuses every UPDATE of `audit_events`, and a delete trigger refuses a DELETE unless the anchor
  covers the row or `audit_archive_rows` lists its seq and hash. `AppendAuditEvent` reads the head and
  inserts the next row in one transaction that holds the head, so processes sharing a store extend one
  chain (`audit.TestTheTriggerStillRefusesAnyOtherDeletion`,
  `audit.TestWritersInSeveralProcessesExtendOneChain`).
- **An identity that leaves leaves nothing but its audit rows.** The test reads the migrated schema for
  every table that names the account, so a table added later is covered the day it is added
  (`TestSQLiteLeaveErasesEveryRowThatNamesTheIdentity`, `TestPostgresLeaveErasesEveryRowThatNamesTheIdentity`).
- **A lease is one holder's at a time** (`TestALeaseIsOneHoldersUntilItRunsOut`).
- **A read-then-write transaction on SQLite is not refused an upgrade** by another writer
  (`TestConcurrentReadThenWriteTransactionsAllCommit`, `TestTwoStoresOnOneSQLiteFileCommitEveryWrite`).

## Held by

In this directory: `store_test.go` (`TestSQLiteConformance`), `postgres_test.go`
(`TestPostgresConformance`, `TestPostgresMigrationsTakeTurns`), `roles_test.go`
(`TestStoreIsOnlyItsRoles`), `sqlc_test.go` (`TestQuerySourcesAreASCII`), `dollarquote_test.go`,
`queryplans_test.go` (`TestEveryQueryHasAPlan`), `leaffingerprint_test.go`, `countplan_test.go`
(`TestCountingContactsByStatusReadsThoseRowsAlone`), `leave_test.go`, `leases_test.go`,
`messages_schema_test.go` (`TestMessagesKeepTheirOrderStatusesAndUniqueness`), `sharedfile_test.go`
(`TestTwoStoresOnOneSQLiteFileCommitEveryWrite`, `TestSchemaCurrentNamesABehindOrAheadSchema`),
`sqlite_contention_test.go`, and the benchmarks in `bench_test.go` and `scale_test.go`.

Elsewhere: `internal/integrationtest/nohandsql_test.go`, `queriesdrift_test.go` and
`layering_test.go` (`TestImportsPointDownTheLayers`); `internal/core/audit/departed_test.go` and
`writer_test.go` for the chain's guards.

The Postgres tests skip without `HDTP_TEST_POSTGRES_DSN`. The pre-push hook starts a Postgres container,
sets it, and so runs them; by hand, `compose.test.yaml` starts one.

## What it does not do

- It writes no audit rows for its own mutations. Callers do, through the audit sink
  (`internal/services/auditsink`); the store only keeps the chain and enforces its shape.
- It does no authorization. Methods take an account id and act on it. Who may ask is decided above, by
  `core/policy` and the surfaces.
- It does no sealing. Secrets (`Account` sealed keys, `Leaf.KeySealed`, settings marked `Secret`,
  integration credentials) arrive already sealed by the keyring and are kept as bytes.
- It does not destroy deleted bytes on Postgres: `Scrub` is a no-op there, and a deleted row's bytes stay
  in dead tuples, the write-ahead log and any backup until the engine reclaims them.
- The conformance suite does not cover everything on the interface. It does not call `AppendAuditEvent`,
  `ArchiveAuditRows`, the change log, leases, presence, `Scrub` or `SchemaCurrent`; those are held by the
  tests above and by `core/audit`.
- A `Contact`'s `Permissions` are stored as JSON text; text that is not valid JSON reads back as an empty
  list rather than an error.
- The generated packages are not edited: a statement changes in `queries/`, the schema in `migrations/`,
  and `make sqlc` regenerates.

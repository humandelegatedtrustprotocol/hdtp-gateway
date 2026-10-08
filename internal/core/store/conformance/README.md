# internal/core/store/conformance

The single test suite every `store.Store` engine must pass (SPEC §11.1). SQLite and Postgres are two
implementations of one interface; this package is how they are kept from drifting apart, because both are
judged by the same tests. It is ordinary non-test Go (its files do not end in `_test.go`) that imports
`testing`, so a test in another package can call it. It sits at rank 2 in the layer table
(`internal/integrationtest/layering_test.go`), above `internal/core/store`. The reachability gate
(`internal/integrationtest/reachability_gate_test.go`) treats it as a package that exists only to be
called from tests, so its calls do not count as production use of a Store method.

Its callers are two tests in `internal/core/store`: `TestSQLiteConformance` (`store_test.go`) and
`TestPostgresConformance` (`postgres_test.go`). It calls the `store.Store` it is handed, through the
interface, and nothing else: it does not know which engine it is judging.

## What it holds

- `Migratable`: `store.Store` plus `MigrateDown`, which the suite needs for the up/down/up check and which
  is not on the interface.
- `Factory`: `func(t *testing.T) Migratable`, returning a new, empty, unmigrated store. The suite migrates
  it; clean-up is the factory's. (`Factory`'s own comment used to say the cleanup "must drop whatever it
  created"; the Postgres caller does not, see below, and the comment now says what the callers do.)
- `Run(t, newStore)`: judges one engine by every area below, in this fixed order, each area a set of
  subtests that start from a fresh store.

| Area (file) | Subtests |
|---|---|
| migrations (`conformance_migrations.go`) | `MigrateUpDownUp`; `MigrateDownAndUpWithDataPresent`, because a down that drops tables in the wrong order works on empty tables and refuses populated ones |
| owners and accounts (`conformance_accounts.go`) | `OwnerCRUD`, `AccountCRUDAndConstraints`, `AccountKeyBindsOnce` |
| contacts (`conformance_contacts.go`) | the lifecycle; `EverActive` set by every activation and cleared by none; the guarded writes that move only from the status read; `RedeemOverPendingContact`; the expiry of pending requests and its clock; `RevokeInvite` scoped to its account; the permissions a contact granted us |
| owner under a chosen id (`conformance_ownerid.go`) | `AnOwnerCanBeCreatedUnderAChosenID` |
| petnames (`conformance_petname.go`) | `PetnameIsLocalAndSurvivesAMove` |
| import and move (`conformance_import.go`) | `AtomicallyLandsEverythingOrNothing`; `MoveFanoutIsOneRowPerContactAndResumable`; `ImportContactWritesWhatAnExportCarries` |
| identity state (`conformance_identity_state.go`) | `IdentityStateRoundTrips` (root, leaf ledger, pins, tombstones, former and pending addresses); `OnePendingRequestAndReplacingItIsOneStep` |
| retention (`conformance_retention.go`) | `RetentionPrimitives`; `ClosedWindowsLeave` (idempotency records and sessions past their window go) |
| settings (`conformance_settings.go`) | `SettingsUpsertAndSecretFlag` |
| credentials (`conformance_credentials.go`) | `CredentialsInsertAndCount`; `RemoveCredentialIfNotLastKeepsTheLastOne` |
| messages (`conformance_messages.go`) | `MsgIDIsScopedToDirection`; `MessageExpiryHoldsAFarFutureDeadline`; `ReadMarkerCountsAndMarksAConversation` |
| memberships (`conformance_memberships.go`) | `MembershipRoundTripAndFK` |
| integrations (`conformance_integrations.go`) | `IntegrationsCRUD` |
| audit pages (`conformance_audit.go`) | `AuditPageScopesToAnAccountAndKeepsTheNodesOwnRows` |

### How a new engine plugs in

Write a `Factory` that opens the engine on an empty database (a fresh file, or a fresh database on a shared
server) and close it in `t.Cleanup`; return it from a test that calls `conformance.Run`:

```go
func TestMyEngineConformance(t *testing.T) {
	conformance.Run(t, func(t *testing.T) conformance.Migratable {
		s := openMyEngine(t) // empty and unmigrated
		t.Cleanup(func() { s.Close() })
		return s
	})
}
```

The two existing callers are the models, and neither drops anything in `t.Cleanup`; each only closes the
store. `TestSQLiteConformance` opens a file in `t.TempDir()`, which the testing package removes.
`TestPostgresConformance` creates a database `hdtp_conf_<n>` on the server `HDTP_TEST_POSTGRES_DSN` names
for each store the suite asks for, after `DROP DATABASE IF EXISTS` on that name, so a database left by an
earlier run is dropped by the next run's factory call and the last run's databases stay on the server. It
skips when the variable is unset.

## What it refuses, and how

It refuses nothing; it reports. A subtest fails with `t.Fatal` or `t.Fatalf` naming the behaviour that
differed. The behaviours that matter across engines are the ones it asserts with `errors.Is`:
`store.ErrNotFound` from `ClearContactHandshake`, from a `RevokeInvite` of another account's invite, and
from `GetSession` of a session the sweep removed.

## Invariants

- **One suite for both engines.** `Run` takes no engine-specific branch: the engines meet it only through
  `Factory`, so a statement that differs in outcome between SQLite and Postgres fails in one of the two
  callers.
- **Each subtest asks `Factory` for its own store**, so a case cannot depend on another's rows.
- **The suite covers the interface where the engines could differ**, and says why in its subtests: for
  example `SumBlobBytes` (Postgres's `SUM(bigint)` is `NUMERIC`, and a scan that missed the type answered
  0), the empty key read (`GetAccountSealedKey` returns no key and no error on both), and
  `Atomically` (a write is visible to the transaction that made it, and a returned error rolls everything
  back).

## Held by

It is the holder, not the held. The two callers above run it; nothing tests the suite's own sensitivity
beyond the fact that two real engines pass it.

## What it does not do

- It does not cover the whole interface. It does not call `AppendAuditEvent`, `ArchiveAuditRows`,
  `SetAuditAnchor`, the change log, leases, owner presence, `Scrub` or `SchemaCurrent`. Those are held by
  tests in `internal/core/store` (`leases_test.go`, `sharedfile_test.go`, `leave_test.go`) and
  `internal/core/audit` (`writer_test.go`, `departed_test.go`), which run on SQLite and, where they
  reach for it, on Postgres.
- It does not prove behaviour under concurrency between processes. `TestTwoStoresOnOneSQLiteFileCommitEveryWrite`,
  `TestPostgresMigrationsTakeTurns` and `audit.TestWritersInSeveralProcessesExtendOneChain` do.
- It does not run Postgres by itself. Without `HDTP_TEST_POSTGRES_DSN`, `TestPostgresConformance` skips and
  only SQLite is judged; the pre-push hook sets the variable.

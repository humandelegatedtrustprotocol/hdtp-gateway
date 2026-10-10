# integrationtest

A package of tests only: it has no non-test Go file, so nothing imports it and `go build` has nothing to compile in it. It holds two kinds of test. The first are scenario tests that stand real nodes up in process (real stores on SQLite and, where a DSN is given, Postgres; real HTTP and TLS listeners) and drive them through the phase exits of PLAN.md. The second are repository guards that read the source tree, the documents, the compose and Envoy files, and `go.mod`, and fail when a claim, a boundary or a list drifts from the code. It has no non-test file, so `layering_test.go`'s rank for it is moot; it builds nodes from `internal/public`, `internal/internalui`, `internal/outbound`, `internal/ingress`, `internal/tunnel`, `internal/integrations`, `internal/contacts`, `internal/messaging`, `internal/identity` and the store (with `internal/testid` for fixtures), and reads files from the module root (and, for two guards, the sibling `harness/` module and the module cache). `TestTheCloudsCopyOfTheOwnerToolsIsCurrent` skips, with a message saying the cloud's copy is unchecked, when the `batondeck` repository is not beside this one. It runs with `go test ./internal/integrationtest/`, part of `make check` (its `test` target). The package comment is in `portal_test.go`.

## What it holds

Scenario tests (one per phase exit)

- `pairing_test.go`: `TestP1ExitTwoNodesPairAndMessage`. Defines `hdtpNode` (a whole node in process: store, identity, public TLS listener with the real per-caller server pool, the production tool set, sealed calls, invite landing page) and `hdtpNet`/`dialMap`, which stand in for DNS because a leaf cannot name a loopback address.
- `portal_test.go`: `TestP2ExitPortalPairing`, run on both store engines by `runPortalPairing`: wizard, invites UI, one-time approval-required invite, redemption to pending, approval UI, owner-agent MCP wait/read/answer, portal inbox.
- `calendar_test.go`: `TestP3ExitContactBooksCalendarSlot`: `check_availability` and `book_slot` served by the Calendar provider through the shipped nspady recipe against an in-test Google Calendar MCP fake (`fakeGCal`), gated by HDTP permissions (one contact may book, the other may only check and does not see `book_slot`).
- `edge_test.go`: `TestEdgeModeSealedSucceedsPlaintextRefusedCertsIgnored` (a terminating edge: sealed calls succeed, plaintext substantive calls fail, client certificates are ignored) and `TestLANFlagOffRefusesDirectConnectionsAndAudits`.
- `ingress_test.go`: `TestP5ExitOwnDomainPassthroughAndTerminate`: one in-process ingress fronting a passthrough node and a terminate node (ACME against Pebble).

Guards over the tree and the documents

- `layering_test.go` `TestImportsPointDownTheLayers`: `layerRank` ranks every package under `internal/` and `cmd/`; a non-test file may import only packages of strictly lower rank. No exception list.
- `nohandsql_test.go` `TestNoHandWrittenSQLOutsideTheStore`: `database/sql`, drivers and goose are imported only in `internal/core/store`; no string literal is a SQL statement; the store's hand-written files run no statement directly.
- `queriesdrift_test.go` `TestQueriesMatchTheHandWrittenCode`: each query in `queries/` is compared with the generated code in both dialects.
- `nogeneration_test.go` `TestNoNameCarriesAGenerationSuffix`, `TestTheGenerationPatternCatchesTheOldNamesAndSparesTheCipher`: no Go identifier or file name under `internal/`, `harness/`, `queries/` carries a protocol-generation suffix.
- `norefreshloop_test.go` `TestNothingRefreshesContactsByItself`: `node.RefreshContact` is reached only from the listed surfaces, never inside a loop or goroutine, never from a function that starts a timer; the `get_card` tool is called only from listed places.
- `wholechain_test.go` `TestOnlyWhatVerifiesTheChainReadsAllOfIt`, `TestOnlyTheArchiveDeletesFromTheChain`: which callers may read the whole audit chain and which may delete from it.
- `auditattr_test.go` `TestEveryAuditRowNamesItsAccount`, `TestAuditOutcomesAreLiteralVerdicts`: audit calls name their account unless the action is node-level; outcomes are literal verdicts.
- `reachability_gate_test.go` `TestEveryMechanismIsReachableFromTheShippedBinary`, `TestDeadcodeFindsOnlyWhatTheTableExcuses`: no package, constructor, exported method or exported function exists with only tests as callers, other than the gaps listed in the "Reachability" table of `docs/conformance.md`.
- `harness_module_test.go` (four tests): the harness is its own module, the root `go.mod` carries none of its dependencies, `go list ./...` excludes it, the image does not copy it.
- `image_toolchain_test.go` `TestImageToolchainSatisfiesGoMod`: the Dockerfiles' `golang` tag satisfies `go.mod`.
- `quickstart_test.go` `TestQuickstartCommandsAreServedByTheImageAndCompose`.
- `localpaths_test.go` `TestNoTrackedFileLeaksALocalPath`: no tracked text carries a path from the machine that wrote it (a home directory on macOS or Linux, an agent scratchpad or job directory); binaries and `third_party/` are not read, and a frozen record of `docs/records.sha256` is left alone while its bytes are the manifest's. `githooks/commit-msg` holds a commit message to the same rule. `TestCommitMsgHookRefusesWhatTheTreeRefuses` runs that hook on planted messages: a macOS home path, a Linux one with and without a trailing slash and one closed by punctuation, a path in a comment line and a path under the scissors (git keeps both for `-m` and `-F`), each refused by the hook and matched by the test's pattern; no path, a route with `home` inside it and a bare `/home` prefix, each kept and unmatched.
- `envoy_test.go` (four tests): `deploy/envoy/envoy.yaml` and `compose.yaml` against what the node reads (chain header, address header, per-address rate limits, connection cap, listener bounds, only Envoy publishes a port).
- `ownertools_fixture_test.go` `TestTheCloudsCopyOfTheOwnerToolsIsCurrent`: the cloud's fixture of this node's owner tool names equals the `mcp.Tool{Name: ...}` literals in the package.
- `statedversions_test.go` `TestEveryStatedWireVersionIsTheOneTheCodeWrites`, `TestTheStatedVersionReaderFindsEachForm`: versions stated in Markdown and Go comments equal what the code writes; frozen records listed in `docs/records.sha256` are skipped while their bytes match.

Guards over the documents

- `conformance_test.go`: `TestConformanceDocCitesRealTests`, `TestConformanceDocLocationsExist`.
- `docclaims_test.go`: `TestReadmeScenarioTableIsTheLiveScenarios`, `TestReadmeAndSpecCiteRealTests`, `TestReadmeTestCountIsAFloorTheTreeMeets`, `TestDocsNameEveryFuzzTargetAndNoOther`.
- `docreview_test.go`: `TestRelativeLinksInTheDocsResolve`, `TestSpecAndTheConformanceMapNameOneHDTPVersion`, `TestSpecNamesEveryReasonAnInstallIsRefused`, `TestOperationsStatesTheBoundTheScaleGateHolds`, `TestTheAuditTrailOfALeaveIsArchivedAfterItsPeriod`.
- `threatmodel_test.go` `TestThreatModelCitesRealTests`: the tests the threat model and review brief cite exist, in this tree or in the pinned identity module.
- `fuzz_targets_test.go` `TestEveryFuzzTargetRunsUnderMakeFuzz`.
- `walk_test.go`: the helper `walkGoTests`, shared by the citation guards. No test of its own.

## What it refuses, and how

It refuses nothing at runtime; it fails the build. Each guard names the file and line (or the document and the claim) and says what to change. Several guards also fail when they read too little (for example `TestImportsPointDownTheLayers` fails if it reads fewer than 25 packages or if `internal/cli` is read as importing fewer than 15 node packages, `TestNoHandWrittenSQLOutsideTheStore` if it sees no files or literals, `TestQueriesMatchTheHandWrittenCode` if it reads too few queries), so a broken reader cannot pass by finding nothing.

## Invariants

These hold because a test here fails otherwise.

- Imports point down the layers (`TestImportsPointDownTheLayers`).
- Only `internal/core/store` touches a database connection or writes SQL (`TestNoHandWrittenSQLOutsideTheStore`).
- Nothing refreshes contacts on its own: a refresh is of one contact, called while a person's request is answered (`TestNothingRefreshesContactsByItself`). This is the guard standing behind the rule that the node does no contact sync except an on-demand refresh of one contact.
- The audit trail is read whole only by chain verification, and deleted from only through the archive (`wholechain_test.go`).
- A claim in the README, SPEC, conformance map or threat model that cites a test cites one that exists.
- The Envoy sidecar's settings equal the node listener's own constants (`public.DefaultMaxConns`, `hdtpnode.PublicHeaderTimeout`, `PublicRequestTimeout`, `PublicIdleTimeout`, `PublicAnswerTimeout`, `PublicMaxHeaderBytes`).

## Held by

The files above are the tests. The scenarios exercise the production tool set (`pairing_test.go` builds the same handlers the binary serves, not look-alikes).

## What it does not do

- `TestTheCloudsCopyOfTheOwnerToolsIsCurrent` checks nothing when the sibling `batondeck` checkout is absent; it skips.
- The reachability gate is a floor, not a proof (its own comment): it counts by bare name, and a function called only from another unreachable function reads as reached.
- `TestNothingRefreshesContactsByItself` reads the syntax tree for `RefreshContact` and `get_card`; it does not observe the running node.
- The envoy tests read configuration; they do not run Envoy (the harness's S23 does, with Docker).
- Build tags are ignored by the reachability scan.
- The scenarios are in process with a stub DNS map; none dials a real network. Postgres runs only where the test is given a DSN.

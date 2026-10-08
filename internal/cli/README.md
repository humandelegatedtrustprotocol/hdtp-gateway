# internal/cli

The hdtp-gateway binary's whole behaviour. `Run` dispatches the command line of SPEC §12.1 (stdlib
`flag`, one subcommand per concern), and the serving composition of SPEC §2.2 lives here too:
`serve` opens the store and the keyring, starts the tunnel adapter, the node, the admin socket and
the internal surface (the portal and the owner MCP), and joins its background work before it closes
the store.

Its caller is `cmd/hdtp-gateway` (`cli.Run(os.Args[1:], version, os.Stdout, os.Stderr)`). It sits
above every other package of the node: `internal/integrationtest/layering_test.go` ranks it 8 and
`cmd/hdtp-gateway` 9. It calls `internal/core` (configuration, keyring, lock, admin socket, store,
audit chain), `internal/node` (the public surface), `internal/identity`, `internal/contacts`,
`internal/messaging`, `internal/portable` (export and import), `internal/integrations` and
`internal/services/*` (settings, audit sink, presence, retention, the integration chain),
`internal/internalui` and `internal/internalui/ownermcp` (portal and owner MCP), `internal/tunnel`,
`internal/ingress` (the ingress role), `internal/limits` (the call-budget client) and
`internal/storecheck`.

Two kinds of command act on a node, and three commands are neither (`version`, `healthcheck`,
which asks the internal listener's `/healthz`, and `ingress serve`, which is the ingress role and
opens no store):

- Admin-socket clients, which act on a node that is running: `account`, `passkey`, `token`,
  `ingress token`. Each sends one named call over the unix socket under the data directory
  (`core.AdminCall`: 5 seconds to dial, 30 to finish) and `serve` answers from handlers it
  registered (`serve_admin.go`). With no node listening the call fails with
  `admin socket: ... (is the node running?)`.
- Direct commands, which read or write the store themselves: `migrate`, `audit`, `export`,
  `import` take the data directory's exclusive lock and so fail while a node serves. `doctor` takes
  it only to find out whether a node holds it, and releases it at once. `check store` takes no
  lock.

## What it holds

Exported:

- `Run(args, version, stdout, stderr) int`: the dispatcher. The commands' output, usage and flag
  errors go to the writers it is given; it returns the exit status.
- `LeaseRenew`, `LeaseTTL`: how often a `serve` process renews the leases on background work
  (10 s) and how long each renewal holds one (three times that). A holder that stops without
  letting go is replaced within `LeaseTTL`; one that stops cleanly, at once.
- `OwnerMCPMaxBodyBytes`: the cap on a request body to the owner MCP (1 MiB).

Unexported, by file:

| File | What it is |
|---|---|
| `doc.go` | the package comment |
| `cli.go` | `Run`, the usage text, `commonFlags` (the `-config` flag every command shares), `loadConfig`, `openStore` |
| `serve.go` | `serve`: the stages in order, the startup banner, the background group |
| `serve_admin.go` | the admin socket's handlers: `ping`, `account.*`, `passkey.*`, `token.*` |
| `compose.go` | `startTunnel`, the internal handler (portal plus `/owner/mcp`), the owner-MCP bearer gate, the landing page hand-off |
| `account.go`, `passkey.go`, `token.go` | the admin-socket clients |
| `leafservice.go` | the signing request and the install of the wallet's answer, one implementation shared by the admin socket and the portal's web-wallet pages |
| `auditcmd.go` | `audit` |
| `portablecmd.go` | `export` and `import` |
| `checkcmd.go`, `doctor.go`, `healthcheck.go`, `migrate.go` | the commands of those names |
| `ingresscmd.go` | `ingress serve` and `ingress token` |
| `capabilities.go` | `capabilityBinder`: which provider serves an account's core capabilities now (mapped mode, SPEC §6.6), resolved per call and cached until an exposure changes |
| `integrations.go`, `integrationsurface.go` | bringing configured integrations back up at start; rebuilding what one integration serves |
| `contactinit.go` | the owner-initiated half of contact establishment (add by card, redeem an invite, request a contact, tell an asker how the owner answered) |
| `ownerextra.go` | what the owner-MCP tools need from outside their package |
| `leases.go` | `leaseKeeper`: this process's share of the leases on the outbound retries and the retention pass |
| `portalurl.go` | the portal address an owner types, the setup URL, the secure-context warning |

### Commands

The flag `-config PATH` (default `$HDTP_CONFIG`) is accepted by every command except `version`,
`ingress` and `__child`. Go's `flag` accepts `-flag` and `--flag`. Where a command has a flag set
of its own (`serve`, `migrate`, `doctor`, `healthcheck`, `export`, `import`, `ingress serve`,
`ingress token`, `check store`, and each `account`, `passkey`, `token` and `audit` subcommand),
`-h` after it prints the flags to the stderr `Run` was given and exits 2. The dispatchers do not
have one: `account -h`, `passkey -h` and `token -h` print only their one-line usage (exit 2),
`ingress -h` and `check -h` answer `unknown subcommand` (exit 2), and `audit -h` reads `-h` as the
subcommand, so it loads the config, takes the lock and opens the store before it prints the usage
(with no data dir it exits 1 with `audit: lock: ...`). `hdtp-gateway --help` is not a flag, it is
an unknown command and exits 2.

| Command | Flags | Prints | Refuses |
|---|---|---|---|
| `version` | none | `hdtp-gateway <version>` | |
| `serve` | `-config` | the startup banner (below), then blocks until SIGINT or SIGTERM; exit 0 on a clean stop | config that does not load; `internal_host` that cannot be a passkey relying party (`core.RuleInternalHostIsRPID`); TLS files that do not load; the data-dir lock (waits up to `core.ServeLockWait` for an exclusive holder, then fails); a schema that is not this binary's while another process serves the same data dir; any stage failing: `serve: <err>`, exit 1 |
| `ingress serve` | `-domain` (required), `-token` or `$HDTP_INGRESS_TOKEN` (required), `-data-dir` (`$HDTP_DATA_DIR`, else `./data`), `-dns` (`cloudflare`), `-cloudflare-token` (`$CF_TOKEN`), `-pair-bind` (`127.0.0.1:8444`), `-data-plane-addr` (the domain), `-data-plane-port` (7000), `-vhost-port` (443), `-internal-vhost-port` (7443), `-key`, `-terminate`, `-acme-email`, `-acme-dir` (`./acme`), `-acme-ca`, `-acme-ca-root` | the domain and key fingerprint, the pairing URL, the data plane address; one `action resource outcome` line per audit event | a missing `-domain` or token: exit 2; an unreadable or certificate-less `-acme-ca-root` with `-terminate`: exit 2; key, data plane, DNS, ACME or listener failures: exit 1 |
| `ingress token` | `-data-dir` | a single-use pairing token, minted by the running ingress (valid 10 minutes) | no ingress listening: exit 1 |
| `migrate` | `-config` | `migrations applied` | creates the data dir; fails while any process holds the lock |
| `doctor` | `-config` | one line per check, `ok`, `warn` or `FAIL`: config, data-dir, lock (held means a node appears to be running, then the admin socket is pinged), store-open, each account's leaf (validity, renewal due, address drift, owed handshakes), tunnel, limits sidecar, public_url guard and reachability probe | exit 1 if any line is `FAIL`; a config that does not load stops it there; warnings do not fail it |
| `healthcheck` | `-config` | nothing on success; one stderr line on failure | exit 0 only if `/healthz` on the internal bind answers 200 within 3 s (https, and only the configured `internal_tls_cert`, when internal TLS is configured) |
| `account create` | `-slug`, `-name` (both required by the node), `-algo` (`p256` default, or `ed25519`), `-endpoint` | `created <slug>  fingerprint <fpr>`, then the signup request (PEM) if the node could name an endpoint | `account: <reason>`, exit 1 |
| `account list` | | `slug`, display name, algo, fingerprint, tab separated | |
| `account csr` | `-slug`, `-purpose` (`signup`, `renew`, `move`), `-endpoint` | the request PEM on stdout; its purpose, endpoint, key and suggested `notAfter` and any `warning:` lines on stderr | |
| `account install-leaf` | `-slug`, `-chain FILE` (two PEM `CERTIFICATE` blocks, leaf then root) | the installed leaf, endpoint, root and expiry; what was retired; whether contacts are being told | no `-chain`: exit 2; a file that is not exactly two certificates: exit 1 |
| `account certificate` | `-slug` | the leaf state, renewal date, owed handshakes, the chain (PEM) | |
| `account address` | `-slug`, then one of `-policy auto\|ask`; or `-root` and `-decision approve\|reject`; or neither (lists contacts waiting at a new address) | the policy now in force; the decision; or `root<TAB>endpoint<TAB>why` per waiting contact | the node refuses a decision that is not `approve` or `reject`, or lacks `-root` |
| `account announce` | `-slug` | how many contacts were told, are waiting, were unreached, refused; whether a walk is under way | an account with no certificate or no leaf yet, or a node not running |
| `account leave` | `-slug`, `-yes`, `-force-current` | without `-yes`, the review of what would be erased and nothing is erased; with it, the erase | refuses when the identity's current leaf names this node's own address for it unless `-force-current`; refuses while a move campaign is walking; a partial erase prints the warning on stderr and exits 1 |
| `passkey list` | | `id<TAB>tag<TAB>owner=<id>` | |
| `passkey remove` | `-id` | `removed` | missing `-id` |
| `passkey reset-wizard` | | a recovery setup URL | |
| `token create` | `-owner`, `-label` (both required), `-account` | the token (shown once) and its id | |
| `token list` | | `id<TAB>label<TAB>revoked=<bool>` | |
| `token revoke` | `-id` | `revoked` | missing `-id` |
| `audit verify` | | `audit chain verified: N events, intact`, plus archive counts | `chain BROKEN` with the row, or the unfinished-archive error: exit 1 |
| `audit export` | | the chain as JSONL on stdout | |
| `audit archive` | `-through SEQ` | `archived N events through seq S to PATH`, or `audit: nothing to archive` | |
| `audit repair` | | `audit: nothing to repair`, or `audit: repaired an interrupted archive; removed N row(s)` | |
| `audit erase-archive` | `-file NAME` | `erased N row(s)` | no `-file`: exit 2; a name that is not in `<data_dir>/audit-archive`; an archive run not finished; the audit row not written: exit 1 |
| `export` | `-slug`, `-out FILE` (both required) | the notice that the file is not encrypted, then `exported <slug> to <file>: counts`, what was left out, ceilings BatonDeck's import would refuse | an existing `-out` file (it is created `O_EXCL`, mode 0600); a file that does not read back through the importer's check is removed: exit 1 |
| `import` | `FILE.zip` first, `-slug`, `-yes` | the review (always), then with `-yes` the counts, and a `next:` text: a request for a new leaf, or, with no `public_url`, the commands to run once there is one; without it `nothing was written` | missing file or `-slug`: exit 2; a file the core refuses: `nothing was written`, exit 1 |
| `check store` | `-config` | `store:` summary line, `NOT READ ...` and `NO PIN ...` lines | exit 1 on any refusal or unknown-state contact; a store that is not migrated is refused and `migrate` is named |
| `__child` | internal | | the resource-cap shim for supervised stdio children (SPEC §6.2); not for operators |

Every `account`, `passkey` and `token` subcommand parses the same flag set, so `account create -h`
lists the flags of all eight `account` subcommands; each subcommand reads only its own. The same is
true of `audit` (`-through`, `-file`).

`serve`'s banner, in order, each line only when it applies: `admin:` (the admin socket is served by
another process on this data dir); `hdtp-gateway serving: data=... internal=...
public=... mode=... tunnel=...`; `public:`; `tunnel:` detail; `limits:` (`... answering` or `NOT
ANSWERING`); `NOT SERVED:` per account whose key cannot be opened; `awaiting a certificate, not
served:` per account with no leaf (naming the `account csr` and `account install-leaf` commands,
with the purpose `signup`, `renew` or `move` the account's history calls for); `address:` where an
account's leaf names another address than the node advertises; the `store:` report of
`internal/storecheck`; and, when no passkey is registered, `portal:` and `setup:` with the setup URL
(valid until a passkey is registered, at most 24 hours), then the secure-context `note:` when the
portal address is not https or loopback.

## What it refuses, and how

Exit statuses: 0 success; 1 the work failed (a message on stderr, `<command>: <reason>`); 2 a usage
error: no command, an unknown command, a flag that does not parse or `-h`, a missing required
argument, an unknown subcommand (but see the last section: for `account`, `passkey`, `token` and
`audit` that is judged after the config has loaded). `Run` with no arguments prints the usage and returns 2.

- Offline commands (`migrate`, `audit`, `export`, `import`) fail at `core.AcquireLock` while any
  `serve` holds the data directory.
- Admin-socket commands fail with `admin socket: ... (is the node running?)` when nothing listens.
- `export` and `import` check their own arguments before opening anything, so a bare verb costs
  nothing and creates no data directory.
- A mutation on the admin socket names the missing argument (`account.create needs slug and name`,
  `account.install needs slug and chain`, `account.address needs slug, root and decision
  approve|reject`, `token.create needs owner and label`, ...) and the CLI prints it with exit 1.
- The owner MCP refuses every request without a valid bearer token before any MCP server is
  composed: `401 a bearer token is required` or `401 that token is not valid` (unknown, malformed
  and revoked tokens get the same answer), each audited (`owner_mcp`). Bodies over
  `OwnerMCPMaxBodyBytes` are refused `413 too_large`, by the bytes that arrive.
- `account leave` is on the admin socket only: shell access on the host is its authorisation, and
  neither the portal nor the owner MCP has it. Without `-yes` it erases nothing.

## Invariants

- No bare `go` statement in this package or in `internal/services/*/`: background work goes through
  `serveWith`'s `WaitGroup`, which is joined before `serve` returns and before the store closes.
  `TestNoGoroutineInThisPackageIsStartedAndAbandoned` fails on a new one; its allow-list holds only
  `ingressServe`, with the reason written out.
- `serve`'s teardown runs in the reverse order of acquisition: background loops, integrations, node,
  tunnel, admin socket, store, lock.
- Every flag set is pointed at the stderr passed to `Run` (`commonFlags`, and `SetOutput(stderr)` in
  the ingress flag sets). `TestRunWritesUsageToTheWritersItIsGiven` holds it for `serve`, `doctor`,
  `healthcheck`, `migrate`, `account create`, `passkey list`, `token create`, `audit verify`, `export`
  and `import`; `check store`, `ingress serve` and `ingress token` are by reading.
- The portal and the admin socket sign and install leaves through one `leafService`, so their audit
  rows, the live node's reload and the move campaign cannot differ.
- The owner MCP is stateless: a bearer token is validated on every request, not once per session.
  `TestOwnerMCPRequiresATokenEvenOnLoopback` holds the requirement; `TestTheOwnerMCPIsStateless`
  holds that a token revoked through the portal's `/owners/tokens/<id>/revoke` route is refused on
  its next request (it does not exercise `hdtp-gateway token revoke`).
- Nothing refreshes contacts by itself: a pin is confirmed when needed and the node does nothing
  proactively (the comment in `startBackground` names `TestNothingRefreshesContactsByItself`, which
  lives in `internal/integrationtest`).
- The documentation's quoted commands are real: `TestDocsOnlyQuoteRealCommands` walks every
  `hdtp-gateway ...` in `docs/`, `docs/demos/` and the repository's top-level markdown and checks
  the command and each flag against the code.

## Held by

All in this directory unless named.

- Dispatch, usage, writers: `cli_test.go` (`TestVersionCommand`, `TestUnknownCommand`,
  `TestMigrateAppliesAndDoctorReportsClean`, `TestMigrateRefusedWhileLockHeld`,
  `TestHealthcheckCommand`, `TestAccountCreateAndListViaAdminSocket`,
  `TestPasskeyCLIAgainstLiveNode`); `writers_test.go`; `doclint_test.go`
  (`TestDocsOnlyQuoteRealCommands`, `TestSpecTablesMatchTheCode`, `TestDemoDocsCarryAManualRunMarker`).
- `serve`: `compose_test.go` (`TestServeRunsTheWholeNode`, `TestServeOwnerMCPBearerGate`,
  `TestServeShutsDownAndReleasesTheLock`, `TestOwnerMCPRequiresATokenEvenOnLoopback`,
  `TestTheOwnerMCPIsStateless`, `TestServeNamesTheAccountsAwaitingACertificate`,
  `TestServeNamesAnAccountWhoseKeyWillNotOpen`); `shareddir_test.go`
  (`TestTwoServesShareOneDataDir`); `healthcheck_test.go`; `background_test.go`; `leases_test.go`
  (`TestTheBackgroundWorkPassesToAnotherProcessWhenItsHolderStops`); `limits_test.go`
  (`TestASidecarThatIsDownIsNamedByTheHealthCheckDoctorAndTheBanner`); `doors_test.go`
  (`TestEveryMutatingPortalRouteRefusesAForgedRequest`, `TestTheOwnerMCPNeverReachesAnotherIdentity`,
  `TestBodiesPastTheCapAreRefusedByTheBytesThatArrive`, and others).
- Accounts and leaves: `walletsign_test.go`, `leafservice_review_test.go`, `leave_test.go`
  (`TestAccountLeaveOnARunningNode`), `hostpolicy_test.go`, `handshake_owed_test.go`,
  `lostkeyring_test.go`, `publicurl_test.go`.
- `audit`: `audit_test.go` (`TestAuditExportThenVerifyGreen`, `TestAuditTamperedExportDetected`,
  `TestAuditRefusedWhileNodeRunning`, `TestAuditArchivePrunesAndKeepsTheChainVerifiable`,
  `TestAuditAnchorCannotBeUsedToHideAWipe`, `TestVerifyFailsWhenTheArchiveIsGone`,
  `TestEraseArchiveRefusals`).
- `export`, `import`: `portable_test.go` (including `TestTheExportVerbsCostNothingWhenTypedBare`),
  `portable_review_test.go`.
- `check store`: `checkcmd_test.go`.
- `ingress`: `ingressacme_test.go`.
- Contacts and offers: `offer_test.go`, `offer_cardsig_test.go`, `offer_fuzz_test.go`
  (`FuzzInviteOffer`), `request_*_test.go`, `notifyasker_test.go`, `contactcap_test.go`.
- Integrations and capabilities: `capabilities_test.go`, `integrationchain_test.go`,
  `stdioenv_test.go`; the owner's audit query: `ownerextra_audit_test.go`.
- `main_test.go` starts one real limits sidecar (`limitstest.LaunchDefault`) for the whole package
  and names it through `HDTP_LIMITS_SOCKET`; the tests need `make limitd` (or `HDTP_LIMITD`).

## What it does not do

- It contains no policy. Budgets are the limits sidecar's, authorisation is the node's and the
  portal's; this package wires them. `compose.go` says the same of itself.
- `serve` does not stop on a store the identity core cannot read: `store:` lines in the banner name
  the rows and it goes on serving. `check store` is the command that exits 1 on them.
- There is no `backup` command (`export` and `import` replaced it); an unknown command exits 2.
- `account`, `passkey` and `token` subcommands are checked after the configuration loads, and
  `audit` after it has taken the lock and opened the store, so an unknown subcommand with a bad
  config reports the config error (exit 1), not the usage (exit 2).
- `ingress serve`'s `-key` help text says "default: <domain>.key in the working directory"; the
  code defaults to `ingress.key` in `-data-dir`.
- No daemon supervision, no config writing: the operator's config file is read, never written.

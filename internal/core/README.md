# internal/core

The foundation under every other package of the node, and a leaf of the layer table
(`internal/integrationtest/layering_test.go`): it imports no other package of the node. It holds the
node's configuration and the rules that resolve and validate it, the keyring that seals secrets at rest,
the data-dir lock, the admin unix socket the CLI reaches a running node through, the redaction applied to
text from elsewhere before it is written down, and a few names several packages share.

The store, the audit chain and authorization are not here but in `core/store`, `core/audit` (with
`core/auditstore`) and `core/policy`, each with its own README.

Callers: `internal/cli` is the wiring and uses nearly all of it (`Load`, `OpenKeyring`, `AcquireLock` and
`AcquireServeLock`, `NewAdminServer` and `AdminCall`, `ApplyStoreSettings`, `ProcessName`, `Tag`);
`internal/node` (`EffectiveSeal`, `Redact`), `internal/public` (`Redact`), `internal/contacts` and
`internal/portable` (`ErrContactCap`, `ContactCapRefusal`; `contacts.ErrContactCap` is the same value, and
`internal/internalui/manage_pages.go` and `internal/internalui/ownermcp/server.go` match it with
`errors.Is` to answer `payment_required`), `internal/integrations` (`ReservedToolNames`,
`ProcessName`), `internal/services/settings` (`EffectiveSettings`, `ValidateSetting`, `SettingsAAD`),
`internal/internalui` (`ValidateSetting`) and `internal/tunnel` (`RegisterTunnel`).

## What it holds

**Configuration (`config.go`, `settings.go`, `nodetag.go`).**

- `Config` is the resolved configuration. `Load(path, lookup)` reads the defaults, the optional JSON file
  (unknown fields are an error) and the `HDTP_*` environment, then calls `Derive`.
- Precedence, highest first (SPEC §12.2): environment, file, the owner-set values from the store, defaults.
  `Config.EnvPinned` and `Config.FilePinned` record which owner-settable knobs the first two fixed.
  `ApplyStoreSettings` layers the store's values under them (it skips a pinned key), re-derives, and
  rejects a key it does not know unless it contains a dot (adapter settings, read by whoever needs them).
- `OwnerSettableKeys` names the knobs the portal may write: `public_url`, `tunnel`, `seal`, `client_cert`,
  `lan_connections`, `limit.contacts`. Everything else is bootstrap. `ValidateSetting` rejects a value the
  resolver would refuse later; `EffectiveSettings` and `Effective` give the settings page each knob's value
  and whether, and why, it is locked; `RestartScoped` names the knobs that take effect on the next start.
- `Derive` runs the rules that depend on resolved values. A tunnel adapter, registered by
  `RegisterTunnel`, derives `Mode`; an edge adapter forces `SealRequired` and `ClientCertOff`. It then
  validates and resolves the LAN flag (default on in direct mode, off in edge).
- Types and values: `Mode` (`ModeDirect`, `ModeEdge`), `Seal` (`SealNone`, `SealOptional`, `SealRequired`),
  `ClientCert` (`ClientCertRequired`, `ClientCertPreferred`, `ClientCertOff`); `EffectiveSeal` is the one
  answer to whether an account requires sealing.
- Derived accessors: `Blobs`, `LimitsSocketPath`, `WalletOrigin`, `ContactCap`, `Tag`; and
  `IsLoopbackBind`, `ParseAuditArchiveAfter`, `ParseCount`.
- Defaults: `DefaultAuditArchiveAfter` ("90d"), `DefaultLimitContacts`, `DefaultWalletURL`.
- The contact cap: `ErrContactCap` is the sentinel (`payment_required`), and `ContactCapRefusal(held, cap)`
  is the owner's message with the count and the cap.
- `NodeTag` is eight hex characters derived from the data dir, public URL and internal bind, put in the
  session cookie's name so two nodes on one host (cookies are scoped by host, not port) do not overwrite
  each other's session.
- `SettingsAAD` is the AAD every secret row of the `settings` table is sealed with.

**The keyring (`keyring.go`).** `OpenKeyring(path, lookup)` resolves the master key, `HDTP_MASTER_KEY`
(base64, 32 bytes) first, then a key file created mode 0600 on first run, and returns a `Keyring`.
`Encrypt(plaintext, aad)` seals with AES-256-GCM, output `nonce ‖ ciphertext`; `Decrypt(sealed, aad)` opens
it. The AAD binds a ciphertext to its column or context, so a value copied between columns fails to open.

**The data-dir lock (`lock.go`).** A flock on `<data_dir>/hdtp.lock`. `AcquireLock` takes it exclusively
and fails at once if anyone holds it; offline commands (`migrate`, `export`, `import`, the `audit`
commands) use it, and `doctor` tries it to learn whether a node is running. `AcquireServeLock` is for
`serve`: exclusive if alone (then the caller migrates and calls `Share`), otherwise shared beside the other
`serve` processes, waiting up to `ServeLockWait` for one that is migrating. `Lock.Exclusive`, `Share` and
`Release` complete it. The kernel releases a flock when the process dies, so a crash does not wedge the
data dir.

**The admin socket (`adminsock.go`).** `AdminServer` serves one JSON request per connection
(`{"cmd": ..., "args": {...}}`, answered `{"ok": true, "data": ...}` or `{"ok": false, "error": ...}`) on
a unix socket of mode 0600, gated by filesystem permissions alone. `AdminSocketPath(dataDir)` places it,
falling back to a path under the system temp dir keyed by a hash of the data dir when the path would be too
long to bind. `AdminCall` is the client. Of several `serve` processes on one data dir, the one holding
`<socket>.lock` serves it and `Serving` reports which.

**Redaction (`redact.go`).** `Redact` replaces credential shapes in text that came from elsewhere:
authorization headers, bearer and basic values, URL userinfo, the query parameters that carry secrets,
JWTs and vendor-prefixed tokens. It matches shapes, not entropy, so HDTP's own high-entropy identifiers
(fingerprints, msg_ids) survive.

**Shared names.** `ProcessName` names this process among all that share a store (host, pid, random bytes),
the holder name of leases. `ReservedToolNames` is every name an integration's tool may not be exposed
under: the built-in tools and `sealed_call`.

## What it refuses, and how

`Load` and `Derive` refuse with an error whose text begins with the rule that was broken; the rule names
are constants:

| Rule | Refuses |
|---|---|
| `RuleInternalBindAuth` | an internal bind that is not loopback (an empty host is not loopback) without `internal_auth_enabled`, `internal_tls_cert` and `internal_tls_key` |
| `RuleInternalHost` | a non-loopback internal bind with no `internal_host`, because no passkey ceremony could succeed |
| `RulePostgresDSN` | `store_engine` `postgres` without `postgres_dsn` |
| `RuleEdgeSeal`, `RuleEdgeClientCert` | edge mode with a seal other than required, or a client_cert other than off |
| `RuleEnum` | a `mode`, `seal` or `client_cert` outside its values, or a tunnel that is not a registered adapter |
| `RuleRange` | an `audit_archive_after` that is not a whole number of days with `d`, or a Go duration, or is negative |
| `RuleWalletURL` | a `wallet_url` that is not an origin: https, or http to a loopback host, with a strict grammar |
| `RuleProxyAddress` | a `proxy_address` that is not an IP address |

`RuleInternalHostIsRPID` is a name only: that check runs where the config is loaded for a command, in
`internal/cli`, because the judgement is the passkey library's and this package imports none.

`ValidateSetting` refuses an owner-set value with `RuleEnum` or `RuleRange`. `OpenKeyring` refuses a
`HDTP_MASTER_KEY` that is not base64 or not 32 bytes, a key file that is group or world accessible, and a
key file that is not 32 bytes. `Decrypt` refuses a value that is too short or does not open under the key
and AAD. `AcquireLock` refuses while any process holds the lock; `AcquireServeLock` refuses after
`ServeLockWait`; `Share` fails if another process took the lock alone in between. `AdminCall` fails with
"is the node running?" when it cannot dial, and returns a handler's error text as the error.

## Invariants

- **Precedence is environment, file, store, defaults** (`TestPrecedenceEnvOverFileOverDefaults`,
  `TestConfigFileOutranksOwnerSetSettings`).
- **Each rule above refuses, and names itself** (`TestRejections`, `TestNonLoopbackInternalNeedsAHost`,
  `TestTheWalletURLIsAStrictOrigin`, `TestAWalletURLThatIsNotAnOriginRefusesTheConfig`,
  `TestTheProxyAddressIsAnIPAddress`, `TestAuditArchiveAfter`).
- **A tunnel adapter derives the mode and forces the edge knobs** (`TestTunnelAdapterDerivesModeAndForcesEdgeKnobs`).
- **The keyring** generates its file on first run with mode 0600, prefers the environment, binds a
  ciphertext to its AAD, fails cleanly under another key, and refuses a world-readable file or a bad
  environment key (`TestKeyringGeneratesFileOnFirstRun`, `TestKeyringEnvBeatsFile`,
  `TestKeyringRoundTripAndAADBinding`, `TestKeyringWrongKeyFailsCleanly`,
  `TestKeyringRefusesWorldReadableFile`, `TestKeyringRejectsBadEnvKey`).
- **`serve` processes share the data dir and an offline command waits for them all**
  (`TestServesShareTheDataDirAndOfflineCommandsWaitForThemAll`, `TestAServeWaitsOutAnotherServesMigration`,
  `TestStoreLockExcludes`).
- **The admin socket** round-trips, answers an unknown command with an error, falls back for long paths,
  and a second `serve` neither takes nor removes the first's (`TestAdminSocketRoundTrip`,
  `TestAdminSocketUnknownCommand`, `TestAdminSocketPathFallsBackForLongDirs`,
  `TestTwoServesDoNotTakeEachOthersAdminSocket`).
- **Redaction removes credentials and keeps evidence**, and a fuzz target holds it (`TestRedactRemovesCredentialsAndKeepsEvidence`,
  `FuzzRedact`).
- **Two nodes a person would run together get different tags**, stable across calls
  (`TestNodeTagSeparatesNodesAPersonWouldRunTogether`, `TestNodeTagIsStableAcrossCalls`).
- **The contact cap is an owner-settable knob with a default** (`TestContactCapIsAnOwnerSettableKnob`).
- **`ReservedToolNames` is the served built-in set**, no more and no fewer:
  `internal/public`'s `TestTheReservedToolNamesAreTheBuiltInSet`.

## Held by

`config_test.go`, `settings_test.go`, `proxyaddress_test.go`, `walleturl_test.go`, `keyring_test.go`,
`lock_test.go`, `adminsock_test.go`, `nodetag_test.go`, `redact_test.go` and `redact_fuzz_test.go` (with its
corpus under `testdata/fuzz`) in this directory, and `internal/public/reserved_test.go` for the reserved
names.

## What it does not do

- It does not hold the secrets the portal writes: those are sealed under the keyring (`Encrypt`, with an
  AAD such as `SettingsAAD`) into the store, and the master key comes from the environment or a key file.
  A credential the operator puts in the file or the environment, such as the password inside
  `postgres_dsn`, is held in `Config` as written.
- It has no OS-keyring source for the master key. The chain of sources is environment, then file.
- It does not watch anything. A `Config` is re-resolved only when a caller runs `Derive` or
  `ApplyStoreSettings`. `RestartScoped` names the knobs that own a socket or a goroutine (`tunnel`,
  `client_cert`) and so take effect on the next start; `LimitContacts` is read per call, as its field
  comment says.
- It does not know the tunnel adapters: `internal/tunnel` registers them at init, and this package only
  asks whether a name is registered and whether it terminates at an edge.
- It does not implement a store, an audit chain or a policy; see the three packages named above.
- `Redact` is not a guarantee: it matches credential shapes, and a token glued to preceding word
  characters (`id=123ya29...`) is not matched, by design, so that it cannot swallow an identifier.

# internal/integrations

The node's client side of upstream MCP servers: it connects to the servers an owner has configured, keeps them healthy, snapshots their tools, and serves the subset the owner exposed to contacts, in one of three modes. Callers are `internal/services/integrationchain` (builds the `Manager`, `Cataloger`, `Exposures` and the OAuth handler per node, `integrationchain.go:83`, `:151`, `:154`), `internal/cli` (`serve.go:340` builds the `Passthrough`; `integrationsurface.go` turns active exposure entries into served tools; `capabilities.go` builds `providers.Calendar`/`providers.Status` from entries in mapped mode; `cli.go:59` dispatches the `__child` mode to `RunChildShim`), `internal/services/presence` (builds `AgentAnswered`), `internal/internalui` and `internal/internalui/ownermcp` (portal and owner MCP). It calls the `store` interfaces, `internal/messaging` (the bus, for agent-answered mode) and the MCP Go SDK. The subpackages `providers` and `recipes` sit on top of it.

## What it holds

Connections and health (`manager.go`)
- `Manager`: one live `mcp.ClientSession` per integration. Transports are `streamable-http`, `sse` and `stdio-supervised`; any other value is refused (`transport`). `Connect`, `Reconnect` (the owner's button; also clears a supervised child's give-up), `Disconnect`, `HealthCheck`, `NoteCallFailure`, `Session`.
- Auth kinds on a row: `oauth` (a handler from `OAuthFor`), `static` (a sealed header attached by `headerRoundTripper` to requests for the integration's own host only), anything else sends no credential.

Catalogue (`catalog.go`)
- `HashTool` is sha256 over canonical JSON of name, description and input schema. `Manager.Snapshot` walks `tools/list` (following cursors) into `[]ToolDef` sorted by name. `Cataloger.Refresh` inserts catalog version N+1 only when the name-to-hash map differs from the latest stored version (`sameToolSet`, `catalog.go:166`); annotations are stored but never hashed. `OnMinted` fires only when a version is inserted.

Exposures (`exposure.go`)
- `Exposures.Publish` mints exposure version M+1 bound to the latest catalog version. `Reconcile` marks entries `Stale` when their confirmed hash is missing or different and mints only if staleness changed. `Reconfirm` rebinds stale entries (all, or those named) to the latest hash. `ActiveEntries` is `AllEntries` minus stale entries. `SnakeName` normalizes exposed names. Modes: `ModePassthrough`, `ModeMapped`, `ModeAgent`.
- `AssessRisk` and `RecipeSuggestion` (`risk.go`) sort and badge the picker; their doc says they are advisory and nothing consults them for authorization.

Dispatch of a contact's call
- `Passthrough.Handler` (`passthrough.go:78`): compiles the snapshotted input schema, validates the arguments against it, checks `Manager.Available` and `Session`, forwards under the snapshot's tool name with `Timeout` (`DefaultCallTimeout` 30 s), and relays the result unless it exceeds `MaxResultBytes` (`DefaultMaxResultBytes` 1 MiB).
- Mapped mode is not served here: `Recipe`, `Binding`, `BuildArgs`, `Lookup`, `LookupString`, `DecodeRecipe` (`mapping.go`) define the field-mapping DSL (field references `$name` and constants only), and `providers` executes it.
- `AgentAnswered.Handler` (`agentanswered.go:102`) parks the call as a pending request and holds it for `DefaultWaitBudget` (30 s); `Answer` (`:159`) records the owner agent's result. A late answer is accepted for `DefaultPendingTTL` (10 min) but not relayed. `RelayWait` is 3 s.

Upstream OAuth (`oauth.go`)
- `NewOAuthHandler` builds the SDK's authorization-code handler. Client identity order: Client ID Metadata Document, then a preregistered client, then RFC 7591 dynamic registration; with none configured it refuses.
- `Connector` carries one portal Connect flow per integration: `Fetcher` publishes the authorization URL, `AuthorizeURL` waits for it, `Deliver` hands in the callback result (newest wins), `Fail` ends a wait with a cause, `IntegrationForState` finds a flow by OAuth state (valid for `stateTTL`, 15 min, several at once), `SetOrigin`/`Origin` remember the browser's origin.
- Secrets: `SealOAuth` (token plus the oauth2 config a refresh needs), `SealStatic`/`OpenStatic`, `SealClient`/`OpenClient` (a preregistered client, stored in the settings table), `ClientKeys` (the settings keys to erase when an identity leaves). Token blobs are sealed with AAD `integration-secret:<id>`.
- Refresh: `persistingSource.Token` serves a valid stored token; an expired one is refreshed by the one process holding the lease `oauth-refresh:<id>` (`RefreshLeaseTTL` 30 s) while others wait up to `RefreshWait` (30 s) and serve what it sealed.

Stdio children (`stdio.go`, `childshim_*.go`)
- `Supervisor` paces restarts: `Gate` refuses with `ErrUnavailable` after `DefaultMaxRestarts` (5) consecutive failures inside `DefaultFailureWindow` (5 min), otherwise sleeps `Backoff(n)` (1 s doubling to 60 s). `BuildCmd` tokenizes argv with `SplitCommand` (shell metacharacters refused), gives the child exactly `StdioConfig.Env` as its environment, and wraps it in the node's own `__child` shim (`RunChildShim`) which applies `RLIMIT_DATA` (default `DefaultMaxMemoryBytes`, 512 MiB) and optionally `RLIMIT_CPU` before exec. `ShimSupported` is true on unix, false elsewhere, where the child runs uncapped with a `Warn`.

## Health and withheld states as the code has them

The store holds a status string per integration: `connecting` (set at the start of `Connect`), `ok`, `unreachable`, `auth_error`, `disabled` (set by `Disconnect`). `failStatus` (`manager.go:235`) chooses `auth_error` for any error `isAuthError` recognizes (SDK OAuth sentinels, `oauth2.RetrieveError`, or a message containing 401, 403, unauthorized, forbidden, invalid_grant, authoriz, oauth), whatever the row's auth kind, and `unreachable` otherwise. Each health cycle (`DefaultPingEvery`, 60 s; negative `PingEvery` disables the loop) pings; on failure it tries a fresh dial. The in-memory `conn` counts consecutive failures: one failure makes `Available` false (calls answer `unavailable`) and sets the status; at `WithholdAfter` (`DefaultWithholdAfter`, 5) `Withheld` becomes true and `OnAvailability(id, true)` fires so the serving layer drops the tools from `tools/list`; the next healthy cycle clears both and fires `OnAvailability(id, false)`. Withheld lives only in memory. `NoteCallFailure` moves the status only for authentication failures seen on a real call. Audit actions emitted: `integration_connect`, `_disconnect`, `_health`, `_recover`, `_withhold`, `_restore`, `_auth`, `_call`, `_child_crash`.

## What it refuses, and how

- Passthrough (`Handler` result, codes in a JSON body `{"code":...}` with `IsError`): `bad_request` for arguments that are not JSON or fail the snapshotted schema (upstream untouched); `unavailable` when the integration is not `Available`, has no session, or the forward fails or times out; `too_large` when the result exceeds the cap (result truncated to the cap and still marked an error). Upstream tool errors are relayed as tool errors.
- Agent-answered: `unavailable` when the pending row cannot be inserted, or on budget expiry/no connected agent when the entry has no `Fallback` or none was supplied. `Answer` reads the request by account and id (`GetAccountPendingRequest`) and returns errors "unknown pending request" (for a missing id and for another account's, alike) and "request is expired or already answered".
- `Exposures.Publish` errors: no catalog snapshot; tool not in the catalog; unknown mode; fallback on a non-agent entry or fallback other than passthrough/mapped; mapped entry without a recipe or exposed name; exposed name equal to a built-in tool name (`core.ReservedToolNames`, non-mapped entries); exposed name not unique across the account's other integrations. Nothing is minted on error.
- `Reconfirm` leaves entries whose tool vanished stale. `Reconcile` returns store errors rather than skipping the guard.
- `SplitCommand`: shell metacharacters, unterminated quote, empty command. `RunChildShim`: unknown flags, missing values, no command; strict failure if `RLIMIT_DATA` cannot be set on Linux.
- OAuth: `NewOAuthHandler` with no client source; `SealStatic` without header and value; `SealClient` without a client id; `OpenClient` for a credential registered to a different integration.
- `DecodeRecipe`: missing name, no capabilities, a capability without tool and kind. `BuildArgs`: a `$field` the provider did not supply.

## Invariants

- The upstream is never consulted for what a call may do: arguments are validated against the snapshot the exposure was confirmed on, not the live schema (`TestSnapshotSchemaGovernsNotLive`).
- A changed tool is withheld until the owner reconfirms it (`Reconcile`, `ActiveEntries`; `TestStaleGuardWithholdsAndReconfirmRestores`). A vanished tool cannot be reconfirmed: it stays stale and withheld (`Reconcile`'s "tool vanished" branch; `TestVanishedToolCannotBeReconfirmed` asserts exactly that).
- A caller's identity never reaches an upstream: `upstreamHTTPClient` consults only the integration row; the static credential is attached only when the request host equals the endpoint's host, so a redirect elsewhere does not carry it (`TestStaticCredentialStaysOnItsHost`).
- Exposed names are unique across an account and never a built-in tool's name (`TestExposedNamesUniqueAcrossAccount`, `TestAnExposureNeverTakesABuiltInName`).
- A child's environment is exactly its allow-list (`TestChildEnvIsExactlyTheAllowList`); argv is never passed through a shell (`TestSplitCommandTokenizesAndRefusesShell`).
- An expired OAuth token is refreshed by one process and served by all (`TestAnExpiredTokenIsRefreshedByOneProcessAndServedByAll`).
- Several authorization states may be pending at once and expire by time, not by eviction (`TestPendingStatesOutliveNewerFlows`).

## Held by

`exposure_test.go` (`TestPublishVersionsAndValidates`, `TestStaleGuardWithholdsAndReconfirmRestores`, `TestVanishedToolCannotBeReconfirmed`, `TestSnakeName`), `reserved_test.go`, `verifyfix_test.go` (`TestReconcilePropagatesStoreErrors`, `TestExposedNamesUniqueAcrossAccount`, `TestDeliverNewestWins`, `TestStaticCredentialStaysOnItsHost`, `TestOAuthFailureLandsAuthError`, `TestSupervisorConfigIsRaceFree`), `catalog_test.go` (`TestSnapshotMintsOnlyOnChange`, `TestToolListChangedTriggersSnapshot`), `manager_test.go` (`TestPingFailureWithholdsThenReconnectRestores`, `TestConnectFailureAudited`, `TestUnknownTransportRefused`), `lifecycle_test.go`, `passthrough_test.go` (schema, truncation, timeout, outage), `agentanswered_test.go` and `agentanswered_shared_test.go` (an answer on one process reaching a call held by another), `oauth_test.go`, `oauth_flow_test.go`, `oauth_shared_test.go`, `stdio_test.go`, `stdio_caps_test.go` (rlimits applied, default cap and explicit uncap, a child over the cap killed), `mapping_test.go`.

## What it does not do

- It does not serve mapped mode itself and holds no calendar logic; that is `providers`.
- It does not decide who may call an exposed tool. `risk.go`'s annotations and name heuristics sort the picker; the hints an exposed tool is served with are `internal/cli`'s `servedAnnotations` over the same stored annotations, and neither gates a call.
- It does not persist the withheld state; a restart clears it.
- It does not hold a caller's token upstream or forward caller identity.
- It does not run stdio children without a supervisor, and on platforms without setrlimit it cannot cap them.

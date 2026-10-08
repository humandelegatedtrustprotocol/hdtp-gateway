# services/integrationchain

The composition root of the integrations (SPEC §6): `Build` wires one `integrations.Manager`, one `Cataloger` and one `Exposures` together and returns them as a `Chain`, so the node and the portal share the same objects and there is exactly one view of an integration's state. `internal/cli/compose.go`, `integrationsurface.go`, `serve.go`, `ownerextra.go` and `capabilities.go` build and use it. It calls `internal/integrations` and the store.

## What it holds

- `Chain`: `Manager`, `Cataloger`, `Exposures`.
- `Build(st, kr, connector, portalBase, auditFn, onSurfaceChange, settingValues, onAttention)` wires:
  - Manager: `Audit`, an HTTP client with a 30 second timeout (`upstreamTimeout`), `StaticHeader` (opens the sealed header of an `auth: static` integration; audits `static_credential` as `unreadable` or `unset`), `StdioConfigFor` (command plus `stdioEnv`), and, only when both `kr` and `connector` are non-nil, `OAuthFor`.
  - `OAuthFor`: opens a pre-registered client if one is sealed; the callback is `<origin the owner's browser used or portalBase>/oauth/callback`; with no client on file it audits `oauth_connect ... method:dynamic_registration started` and registers a public client with PKCE (`TokenEndpointAuthMethod: none`), and `OnRegistered` seals what registration mints for the next flow.
  - Cataloger: `OnMinted` runs `Exposures.Reconcile` (the §6.5 stale guard) and audits `exposure_stale_guard ... narrowed` when it changed something.
  - Manager hooks `OnConnected`, `OnHealthy` and `OnToolListChanged` take a catalog snapshot (`Cataloger.Refresh`, bounded by the 30 second timeout); `OnAuthError` is `onAttention`; `OnAvailability` audits `integration_availability` as `withheld` or `restored` and calls `onSurfaceChange`.
- `StdioEnvPrefix` = `"env."`: a supervised child's environment is the settings rows `integration.<slug>.env.<NAME>` (`stdioenv.go`). Its values are sealed at rest when the name looks like a credential (the settings service decides).

## What it refuses, and how

`Build` itself returns no error. A failing `StaticHeader` returns its error to the manager after auditing `static_credential` `unreadable`. `OAuthFor` returns the error from opening the stored client. `stdioEnv` degrades rather than fails: if the settings read fails it audits `stdio_env ... unreadable` and the child gets only PATH and HOME.

## Invariants

- A stdio child gets an allow-list, not an inheritance: `PATH` and `HOME` from this process (when set), plus the `integration.<slug>.env.*` rows for its own slug. An owner-set `PATH` replaces the default. No other variable of the node's environment is passed (`stdioenv.go:23-48`).
- Rows of another integration's slug, and the integration's non-env parameters, never enter the child's environment.
- Reconcile can only narrow what contacts reach, so running it automatically on every new snapshot is safe in the direction that matters (comment at `integrationchain.go:155-159`).

## Held by

- `integrationchain_test.go`, `TestIntegrationChainIsWired`: the manager has `Audit` and a client with a timeout; `OnConnected`, `OnHealthy`, `OnToolListChanged`, `OnMinted`, `OnChange` and `OnAvailability` are set; the cataloger snapshots the same manager; a withhold calls the surface-change function once and is audited `integration_availability withheld`; `OnMinted` on a bare integration does not fail. It asserts the wiring exists, not that each hook fires.
- `stdioenv_test.go`: `TestStdioChildGetsItsConfiguredEnvironment` (configured rows reach the child, other slugs' rows, recipe parameters and `tunnel.*` do not, PATH and HOME are present), `TestStdioEnvIsAnAllowListNotAnInheritance` (owner `PATH` wins; a variable set in the test process does not leak; at most three entries), `TestChainWiresStdioConfigForOntoTheManager` (`Build` installs `StdioConfigFor` carrying the command and the configured env).

## What it does not do

It does not hold the integrations' logic (that is `internal/integrations`), does not open OAuth for static or `none` integrations, and wires no `OAuthFor` when there is no keyring or connector. The `stdioEnv` key is built from the slug alone; the account id is used only in the audit resource.

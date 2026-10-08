# services/settings

The owner-set configuration layer (SPEC §8.2, §12.2): settings rows are read from the store at startup, layered under the environment, and written back by the portal. A save either takes effect in the running node or is marked restart-scoped. `internal/cli/serve.go` builds the `Service` and calls `Values`, `Follow` and `Deps`; `internal/cli/serve_admin.go` and `doctor.go` also use it; `internal/services/retention` reads its windows through `RequestExpiryFor` and `StorageFor`. It calls `internal/node`, `internal/messaging` (the event bus), `internal/contacts` (presets, default expiry), `internal/identity`, `internal/ingress`, `internal/tunnel`, `internal/internalui` (the page's dependency struct) and the store.

## What it holds

- `Service` (`New(st, kr, cfg, audit)`): `AttachNode`, `AttachBus`, `SealPolicy`, `Follow`, `Values`, `Deps`, `ContactCap`, `RequestExpiryFor`, `StorageFor`.
  - `Values` returns every stored setting with secrets decrypted; it is the startup path and the only decrypting read. The render path (`plainValues`) skips secret rows and every dotted key.
  - `save` validates with `core.ValidateSetting`, seals the value when `isSecretKey` says so (the last dotted segment, lower-cased, contains `token`, `key`, `secret`, `password`, `auth`, `credential`, `passwd`, `apikey` or `pat`), stores it, applies it, and publishes a settings event on the bus.
  - `apply` pushes into the running node only `limit.contacts`, `seal`, `lan_connections` and `public_url` (`settings.go:324-395`); every other knob waits for a restart. With no node attached, a save is stored only.
  - `Follow` applies, until `ctx` ends, the settings other processes on the store saved (events with `Local` false), as the saving process applied them, without re-auditing and without re-sealing accounts.
  - `Deps` builds `internalui.SettingsDeps`: effective settings, save, adapter settings (names and set-ness of `tunnel.*` rows, never values), pairing and unpairing, per-account storage rows, presets (`savePreset` seeds every resolved bundle on first write; `deletePreset` of the last row restores defaults), and the reachability probe.
- Per-account keys: `StorageKeyQuota` (`storage.quota.<id>`), `StorageKeyRetention` (`storage.retention.<id>`), `ContactsKeyRequestExpiry` (`contacts.request_expiry.<id>`), and `AccountKeys(accountID)`, the list of all three, which `identity.Manager.Leave` erases.
- `MaxRetentionDays` = 36500. `RequestExpiryFor` reads the owner's days when 1 to `internalui.MaxRequestExpiryDays` (365), else `contacts.DefaultRequestExpiry` (30 days). `StorageFor` returns quota bytes and a retention window; zero is default quota and unlimited retention.
- Ingress pairing (`ingresspair.go`): `pair` runs the one-time-token exchange with `ingress.Pair`, stores the result as `tunnel.<adapter>.*` rows with `subdomain` written last, then selects the adapter and sets `public_url`; `unpair` deletes the pairing rows; `PinnedIngress(adapter, stored)` returns the ingress fingerprint only for `ingress-terminate`.
- `LeafAddress(ctx, st, accountID)`: the endpoint of the account's current leaf, or empty. `ServedIdentities(publicURL, accts)`: for each account with a root, its root fingerprint and the endpoint a leaf must name here (used by the probe).

## What it refuses, and how

- `save`: the error from `core.ValidateSetting` for an invalid key or value; store and keyring errors pass through.
- `Values`: `settings: <key> is corrupt` for a sealed row that is not valid base64; for a row that cannot be opened with the keyring, `settings: <key> cannot be opened with this keyring` when the key is top-level (seal policy, certificates and reachability must not start under an unknown posture), but a dotted key is audited `settings_unreadable ... skipped` and left out so the node can start (`settings.go:171-186`).
- `pair`: `the node is not serving yet` with no node attached; `create an account before pairing`; `unknown account`; `this node has several identities — choose which one to pair` when none is named and there are several; an ingress refusal is audited `ingress_pair ... refused` and nothing is stored.
- `unpair`: `"<x>" is not an ingress adapter`; and refuses while that adapter is the running or the stored `tunnel` selection (`ingresspair.go:138-158`).
- `SaveStorage`: `unknown account` for an id the store does not have.

## Invariants

- A secret goes in and never comes back out through rendering: the page reads only non-secret top-level rows and, for adapters, names plus `Set` flags. Credentials are sealed with the node keyring under `core.SettingsAAD()` before they touch the database.
- A pairing write that fails partway is not selectable: `subdomain` is written last, and `pairedAdapters` treats it as the marker.
- A changed `public_url` moves nothing by itself: accounts keep answering at the endpoint their leaf names; for each account whose leaf was certified for the node's old derived address, an `account_move_needed` audit row names the move (`settings.go:380-392`).
- `AccountKeys` names every per-account key function in the package.

## Held by

- `accountkeys_test.go`, `TestAccountKeysNamesEveryPerAccountKey`: parses the package's non-test sources for functions taking one `accountID string` and returning one string, requires at least three, and checks each key is in `AccountKeys`.
- `secretkey_test.go`, `TestUppercaseCredentialsAreSealedAtRest`: saves four `integration.<slug>.env.<UPPERCASE>` credentials and asserts each stored row is marked secret and does not contain the plaintext.
- `shared_test.go`, `TestASettingSavedOnOneProcessIsAppliedByAnother`: two processes on one store; `seal`, `lan_connections` and `public_url` saved on one are applied on the other, which writes no audit row.
- `presets_test.go`, `TestPresetEditingSeedsAndRestores`: the first preset write seeds the other bundles; a deleted last row restores defaults.

No test in the package covers `pair`, `unpair`, `RequestExpiryFor`/`StorageFor` bounds, the `Values` corrupt/unreadable paths or `ServedIdentities`; do not cite these as held.

## What it does not do

It does not apply restart-scoped knobs live, does not render or return a secret, and does not validate adapter settings by the owner-knob rules (`saveRaw` skips `core.ValidateSetting`; the adapter owns its shape). `unpair` does not delete the stored `ingress_fpr` row (its key list is subdomain, domain, data_plane_addr, data_plane_port, data_plane_token, node_fpr, node_secret). A `public_url` change does not announce anything to contacts.

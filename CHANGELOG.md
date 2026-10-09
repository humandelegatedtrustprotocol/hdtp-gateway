# Changelog

Notable changes to hdtp-gateway. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will use
[semantic versioning](https://semver.org/spec/v2.0.0.html) from its first release.

The first release is 0.1.0. The per-change record before it — every task, every defect,
how each was proved — is in [`PLAN.md`](PLAN.md), which is more detailed than a
changelog can be and is not summarized into a fictional release history.

## [Unreleased]

### Changed

- A removed contact's conversation stays in the inbox, under the name it had (the owner's petname,
  else theirs) and ` · removed`, readable and with no composer; it used to vanish from the list
  with the contact. A conversation whose contact is now a request or blocked stays listed too,
  read-only, under that row's name. Migration 0002 keeps the names on the contact's threads as its
  row is deleted, by any path, and never replaces a kept name with an empty one; `get_inbox`
  answers them as `removed_contact` (SPEC §9.1).

### Fixed

- The sealed answer to `get_card` carries the node's chain whatever the node has recorded the
  contact as having seen (HDTP §13.2: `get_card` "always answers with the chain"). It followed the
  record, so a contact that could not verify an answer and asked `get_card`, as §13.2 says to, got
  the fingerprint of the leaf it could not verify, and stayed stuck until that leaf retired. The
  answer is recorded as the chain sent, like any chain-form answer.
- An answer from a peer whose card says `X-HDTP-SEAL: required` that verifies under no leaf held for
  it is followed by one `get_card`, sealed to the pinned leaf, and when the chain it answers with is
  newer than the pin, by a re-pin and one retry under the same `msg_id`. The call failed at once,
  with the pin standing until an answer carried the chain or the pinned key retired. A `get_card`
  that does not verify, or is refused (`certificate_renewed` when the pinned key retired in
  between, which the next call follows), ends the call with an error naming both failures; no
  second `get_card` is asked. A peer that takes plaintext is still asked in plaintext.

## [0.1.2] — 2026-10-09

### Added

- Deploy templates for one VM with TLS on a hostname (`docs/deploy.md`): a shared first boot
  (`deploy/cloud-init.yaml`: Docker, the node and its sidecar built from a release tag, Caddy in
  front), a CloudFormation template for AWS, an ARM template with a Deploy to Azure button, a Cloud
  Shell walkthrough for Google Cloud and a Droplet script for DigitalOcean. `make deploy-check`, in
  `make check`, holds the templates to each other and to the node (`scripts/deploy-check.mjs`).
  None has been run on its provider yet; the document's status table says so, per provider.

### Security

- Built with Go 1.26.9 (13 standard-library advisories fixed since 1.26.6; v0.1.1's binaries were
  built with 1.26.6). `go.mod` names it in a `toolchain` line, the Dockerfiles pin
  `golang:1.26.9-alpine` by digest, and the image test holds the two to each other.

### Fixed

- The portal's integration routes refuse an integration of another account with `404`, the answer
  an id that names no row gets. `POST /integrations/{id}/remove` refused it `403`; the other eight
  (`oauth-client`, `credential`, `connect`, `authorize`, `refresh`, `exposure` read and write,
  `reconfirm`) compared nothing, so an owner who administers one account could connect,
  re-credential, refresh, read and set the exposure of another account's integration by naming
  its id.
- The limits sidecar's container has a healthcheck of its own: `hdtp-gateway healthcheck --limits`
  asks the sidecar for its rules over the socket the node asks it on. It inherited the image's,
  which asks the node's portal, so `docker compose ps` listed `limitd` unhealthy for as long as it
  ran; `compose.yaml` and `deploy/envoy/compose.yaml` run the new one.
- `doctor` reads `public_url` the way the node does: the environment, else the configuration file,
  else what the portal's Settings saved. It read the first two alone, so on a node whose address
  was set in the portal it printed `warn probe skipped: public_url not configured` and never
  dialled it.
- The owner MCP's `set_exposure` answers an integration of another account as it answers an id
  that names no row: the same `bad_request` detail, and no `permission_denied` audit row of its
  own. It read the integration's catalog before comparing accounts, so the catalog read's error
  told a foreign id from a missing one — an existence oracle the portal's `404` does not have.
  Both doors now ask the store for the integration by account and id (`GetAccountIntegration`),
  which answers `ErrNotFound` for either.
- The portal refuses a `POST` whose form fails to parse with `400` "bad form" (audited `bad_form`)
  before any route, and the CSRF check refuses one too. `ParseForm` keeps the pairs that parsed,
  and the account check read the body only when it parsed cleanly, so `account=<another's>&x=%zz`
  (or a bad escape in the query) reached the handler unchecked and acted on that account.
- The portal's `GET /events` carries only the events of accounts the signed-in owner administers.
  With several accounts and none named it subscribed to every account's, so an owner read the
  live stream of accounts administered by another owner.
- The owner MCP's `answer_request` answers another account's request id as it answers an id that
  names nothing (`unknown pending request`). It read the request by id and compared accounts after,
  so a token narrowed to one account told which request ids existed on another. The store reads and
  answers a pending request by account and id (`GetAccountPendingRequest`, `AnswerPendingRequest`).
- An answer from a contact whose card requires sealing that cannot be verified under any leaf held
  for it fails at once, with an error that says the pin stands until an answer from the contact
  carries the chain. The node tried its remedy first, a plaintext `get_card`, which refuses itself
  against such a contact before sending, and the error named that refusal (`and get_card:
  seal_required`). Against a contact that takes plaintext the remedy stands: one plaintext
  `get_card`, its chain followed to the pinned root, then one retry.

### Changed

- `web/tools/portal-qa.mjs` is removed: nothing ran it, and the harness and `make screenshots`
  cover what it drove.
- `make gosec` excludes `.claude`, the checkout's worktrees, which gosec's own filesystem walk
  entered and the Go tool's `./...` never did.
- `make analyze` runs its tools under the Go `go.mod` names (`GOTOOLCHAIN=<toolchain>+auto`), so a
  machine with an older Go, or `GOTOOLCHAIN=local` set, downloads it instead of failing. A Go older
  than 1.21 has no toolchain switching and is not helped.

## [0.1.1] — 2026-10-09

### Fixed

- The portal's session gate is an allow-list. A `GET` of a registered route outside `/api/` fell
  through to its handler with no session: `GET /media/{hash}?account=<id>` answered the stored
  bytes and `GET /events?account=<id>` opened the account's event stream to anyone who could reach
  the portal. Without a session the portal now serves the sign-in and setup ceremonies,
  `/api/session`, the wallet's return page, `/oauth/callback`, the static shell and the SPA's views;
  every other `GET` is sent to sign in, and a fetch under `/api/` or a mutation is refused `401`.
- `POST /messages/send_media` acts on the account the query names, which account resolution checks
  against the owner's memberships. It took the account from the multipart body first, which
  resolution never reads, so a signed-in owner could send media as an account they do not
  administer; the same id in the query was refused `404`.
- `list_passkeys` and `remove_passkey` on the owner MCP refuse a token narrowed to one account
  with `permission_denied`, as every account-scoped tool does; any valid token could list and
  remove the owner's passkeys. `remove_passkey` of an id that names no passkey answers
  `not_found`, where it returned the raw error.
- `wait_for_updates` answers when a contact is parked at a new address (`pending_addresses`) or an
  integration needs re-authorizing (`needs_attention`); the node woke the wait for both and the
  wait parked again until its timeout.
- An ingress pairing writes `subdomain`, the marker that makes the adapter selectable, as the last
  of its rows. `ingress_fpr` was written after it, so a failure on that write left a selectable
  adapter with no ingress pin; `unpair` now deletes `ingress_fpr` with the other rows.
- `GET /oauth/callback`, served without a session, completes a flow only for a `state` the node
  minted: it no longer takes an integration id from the query, no longer creates a connector
  entry per id it is given (unbounded from an unauthenticated request), no longer writes a
  result with a foreign state into an owner's pending flow, and audits the callback under the
  integration's own account rather than an `account` named in the query.
- `SPEC.md` §8.3 names the requests the portal serves without a session as the gate's
  allow-list has them (`/api/session`, the wallet's return page, `/oauth/callback` and the SPA's
  views among them); it said only the ceremonies, the shell and the health probe were served.
- `SPEC.md` §5.4 and §12 said a pending-tier caller invoking a tool beyond its own is refused
  `permission_denied`. The node answers `pending_approval` (`refusalCode`,
  `TestThePendingTierIsRefusedPendingApproval`), as HDTP 1.0 amended by SEP-0003 requires; the
  two lines say so.

### Removed

- `DashboardDeps.Setup` and `DashboardDeps.SignedIn`, set by the composition and read by nothing,
  and `ownermcp.ErrNoCard`, returned by nothing.

## [0.1.0] — 2026-10-08

This release covers the surfaces described in [`SPEC.md`](SPEC.md):

### Added

- **Node role** — the personal HDTP server: contacts, invites, a per-contact
  permission switchboard, messaging with threads, media with quotas, availability and
  calendar booking, all as MCP tools over mTLS with sealed envelopes.
- **Ingress role** — an own-domain front door for one or more nodes, in passthrough
  (SNI-routed, end-to-end) or terminate (ACME certificate, re-originated) mode.
- **Portal** — the owner's private web surface: setup wizard, passkey login, contacts
  and requests, inbox, integrations, settings, identity and key rotation.
- **Owner MCP** — the same authority for the owner's own agent, behind named,
  revocable bearer tokens on every bind.
- **Integrations** — upstream MCP servers over streamable-HTTP, SSE or supervised
  stdio, exposing only the tools the owner picks, versioned and audited, with recipes
  mapping them onto HDTP capabilities.
- **Reachability** — direct, Tailscale, frp, ngrok, Cloudflare, or the ingress role,
  with a `doctor` that derives the deployment mode and probes the endpoint.
- **Storage** — SQLite by default, PostgreSQL when wanted, with backup and restore;
  `check store` and the `serve` banner read every card and certificate the store holds
  by the identity core's rule and name each that does not read, and name each contact
  in a state neither a pin nor a request has.
- **Audit** — an append-only hash-chained trail over every public call and every
  configuration change. The rows naming an identity that left the node move to an
  archive file of its own after `audit_archive_after` (90 days by default), and verify
  with the rest of the chain (SPEC §3.11).
- **`THIRD_PARTY_NOTICES`** — the licence text of the Go modules the binary links, the
  crates the limits sidecar builds and the npm packages the portal bundles, written by
  `make notices` and held to `go.sum`, `Cargo.lock` and `package-lock.json` by
  `make notices-check`, which `make check` runs; a release ships the file.

### Changed

- The identity module, `github.com/humandelegatedtrustprotocol/hdtp-identity/go`, comes
  through the public Go module proxy and checksum database: hdtp-identity is public since
  2026-10-08, so `GOPRIVATE`, the SSH `insteadOf`, `make identity-proxy` and the
  `identityproxy` image-build context are gone, and a clone builds, vets and gates with no
  credential.
- The docs say where the identity repository is, where they said it was not public: the
  README quickstart, CONTRIBUTING, RELEASING, the pre-push hook, `docs/testing.md`,
  `docs/crypto-review-brief.md`, `docs/harness-design.md` and `docs/operations.md`.
- `compose.yaml` pins `alpine/socat` and `cloudflare/cloudflared` by digest (each `:latest`
  as resolved on 2026-10-08), the tag kept beside the digest for the reader.

# Changelog

Notable changes to hdtp-gateway. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will use
[semantic versioning](https://semver.org/spec/v2.0.0.html) from its first release.

The first release is 0.1.0. The per-change record before it — every task, every defect,
how each was proved — is in [`PLAN.md`](PLAN.md), which is more detailed than a
changelog can be and is not summarized into a fictional release history.

## [Unreleased]

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

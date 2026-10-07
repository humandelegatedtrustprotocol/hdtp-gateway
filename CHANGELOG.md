# Changelog

Notable changes to hdtp-gateway. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will use
[semantic versioning](https://semver.org/spec/v2.0.0.html) from its first release.

Nothing has been released yet, so there is no history below to reconstruct. What
exists is one unreleased version. The per-change record — every task, every defect,
how each was proved — is in [`PLAN.md`](PLAN.md), which is more detailed than a
changelog can be and is not going to be summarized into a fictional release history.

## [Unreleased]

The first release will cover the surfaces described in [`SPEC.md`](SPEC.md):

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

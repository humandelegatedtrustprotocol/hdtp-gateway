# Operating a pact-gateway node

This is the operator's page: what runs where, how the node is reached, how it is
backed up, and what to do when something is lost. Design rationale lives in
[`SPEC.md`](../SPEC.md); this page only tells you what to run.

## Layout

| Path (in `data_dir`, `/data` in the container) | What |
|---|---|
| `pact.db` | the SQLite store: accounts, contacts, messages, integrations, audit chain |
| `blobs/` | content-addressed media |
| `keyring.key` | the keyring master key (0600). **Every account's private key is sealed under it.** |
| `pact.lock` | held while `serve` runs; offline commands refuse to run while it is held |
| `admin.sock` | the admin socket the CLI talks to while the node is running |

Configuration: env `PACT_*` > `config.json` > defaults (`pact-gateway doctor` prints the
resolved result). The deployment **mode is derived** from the tunnel adapter, never
declared (SPEC §10.1).

## Reachability

| You have | Use | Mode |
|---|---|---|
| a public port / static IP / VPS | `tunnel: direct` (default) | direct |
| a Tailscale account | `tunnel: tailscale` — tsnet Funnel, free, ports 443/8443/10000 | direct |
| an `frps` you run on any VPS | `tunnel: frp` — raw SNI/tcp passthrough | direct |
| a paid ngrok plan | `tunnel: ngrok` — `tls://` endpoint | direct |
| a Cloudflare account | `cloudflare` edge adapter (P4-05) — Cloudflare terminates TLS | edge |
| a domain of your own | run a second pact-gateway in the **ingress role** on a VPS (below) | direct (passthrough) or edge (terminate) |
| nothing inbound at all | one of the tunnels above, or a provider hosting the identity under a leaf you issue (PACT §9). There is no relay role: it went with PACT 1.x on 2026-09-18, because a store-and-forward gateway sees every sender, recipient and timestamp | — |

Direct mode keeps mTLS end to end: callers' client certificates reach the node. Edge
mode cannot — a third party terminates TLS — so the node **forces** `seal=required`
and `client_cert=off`, and callers are identified by their sealed-envelope
signatures. `pact-gateway doctor` reports the derived mode and probes your
advertised endpoint; a `wrong_cert` verdict means something between the caller and
the node is terminating TLS that should not be.

Every carrier still sees metadata (who talks to whom, sizes, timing). Where that is
itself sensitive, use `direct` on infrastructure you control (SPEC §13).

### Ingress role (own domain)

On the VPS run the ingress; on the node pair with a one-time token:

1. ingress: `pact-gateway ingress serve --domain example.com` (P5-05 wires the command;
   the library is `internal/ingress`) and mint a token from its portal.
2. node: portal → *Settings → Ingress* — paste the token, pick the subdomain and mode:
   - **passthrough** — the ingress routes on SNI and forwards raw TLS; your node's own
     certificate is what callers see (direct mode).
   - **terminate** — the ingress holds an ACME certificate, terminates the public TLS
     session, and re-originates a mutually-pinned mTLS leg to your node (edge mode for
     your node). Both keys are pinned at pairing; nothing else can deliver traffic.
3. The node connects **outbound** (embedded frp client) — no inbound port at home.

## Call budgets

Every call counts against its caller's hourly budget: PACT §12 sets 60 an hour
for a contact and 10 for a guest, and a guest is counted per IP *and* key so one
address cannot exhaust every guest and one key cannot hop addresses. A refusal
is a `rate_limited` tool error and an audited `rate_limited` row, not a dropped
connection — the caller's agent can read it and back off.

Those numbers are defaults, not a ceiling. Two busy agents can legitimately
exceed sixty calls an hour, so both are settings:

| Setting | Environment | Default | Meaning |
|---|---|---|---|
| `limit.contact_per_hour` | `PACT_LIMIT_CONTACT_PER_HOUR` | 60 | calls per hour per contact |
| `limit.guest_per_hour` | `PACT_LIMIT_GUEST_PER_HOUR` | 10 | calls per hour per guest IP+key |

Both are ordinary knobs: the portal's Settings page edits them under Security,
the config file carries them as `limit_contact_per_hour` and
`limit_guest_per_hour`, and the environment pins them above both (SPEC §12.2),
in which case the page shows them locked and says why.

They are read per call, so a change takes effect immediately with no restart.
Empty, zero or unparseable restores the documented number rather than removing
the cap: a bad row must not open the gate.

The counters live in memory. A restart gives every caller a fresh window, which
is the trade-off for not writing to the database on every call — the budget is
there to blunt abuse, not to meter usage, and an attacker who can restart your
node has already won. Memory is bounded: keys whose window has emptied are
swept once per window, so a caller cycling addresses or fingerprints cannot
grow the table indefinitely.

## Export and import

```
pact-gateway export --config config.json --out alina.pact-export
pact-gateway import --config config.json --from alina.pact-export
```

Both are **offline** commands: stop the node first (they refuse while `pact.lock` is held).

**An export is a person's contacts and chats, and nothing else.** For each identity that has a
root: its name (slug, display name, the root's fingerprint and certificate — all public), its
contacts as pinned, and its conversations with their media. It is written through the node's
`Store` interface, so it is an allow-list by construction, and it works on Postgres exactly as on
SQLite. It is a gzipped tar of a manifest, `data.jsonl` (one JSON object per line, five kinds) and
`media/<sha256>`; the manifest carries the digest of the data, and the file is created `0600` and
never replaces an existing one.

What is **not** in it, because it is the host's and not the person's: every key (leaf keys, and
`keyring.key`, which used to ride along), saved settings, integration credentials, owners, passkeys,
sessions, tokens, invites, the audit chain, and the ledger of leaves. There is no flag that adds
any of them.

`import` creates each identity — it never merges into one that is already here, by slug or by
root — under ONE transaction, so a refused or interrupted import leaves nothing behind. It is
strict: a member, a kind of line, or a single field it does not know is a refusal. An undelivered
outbound message arrives as `failed`: delivering it was the old host's job, under the old host's
leaf.

Every import ends the same way. The identities are **named and not served**; `serve` prints the
`account csr` to run for each, the wallet signs it, and `account install-leaf` ends the wait — and,
the identity having arrived from elsewhere, starts the move campaign that tells its contacts.

This is not a backup of the node, and the node has none: what a host accumulates beyond contacts
and chats is rebuilt, not restored. After a lost machine: `import`, the setup wizard for a passkey,
reconnect integrations, one certificate per identity.

## Recovery

| Lost | Consequence | Do |
|---|---|---|
| the node, with an export | identities are not served until re-certified; settings, integrations, passkeys and the audit history are not in an export | `import`, `serve`, the setup wizard; then one `account csr` / `install-leaf` per identity. Contacts keep their pins |
| `keyring.key` only | sealed leaf keys, saved settings and integration credentials are unreadable. **No identity is lost** — the root is in the wallet. If nothing on the node opens under the master key it was given, `serve` refuses to start and says why; if anything does, it starts and prints `NOT SERVED` for each account that does not | put the key back if it was kept anywhere, and nothing is lost. If it is gone for good: `export`, then `import` into a fresh data directory — an export never needed the master key, because it never held anything sealed under it. For a single `NOT SERVED` account on a running node, a renewal alone does it: the install retires the key it cannot open and says so |
| a leaf simply ran out (nobody renewed it) | the account stops being served within the hour and its key is destroyed; contacts keep their pins, and `doctor` warns before it happens | `account csr --slug me -purpose renew`, the wallet signs, `account install-leaf` |
| one account's leaf key (compromised) | the thief speaks as that host until the leaf expires or is outranked | `pact-gateway account csr --slug me -purpose renew`, have the wallet sign it, `account install-leaf`: the newer leaf outranks the stolen one with every contact it reaches (PACT §14.3) |
| the wallet's root | the identity itself; this node cannot help | the wallet's own recovery, if it has one (PACT §9, §14.5) |
| the audit chain shows a break | someone altered history | `audit verify` names the first bad row; treat the store as untrusted from there |

No telemetry leaves the node, ever; the audit chain is yours alone.

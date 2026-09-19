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

## Backups

```
pact-gateway backup create  --config config.json --out pact-backup.tar.gz
pact-gateway backup restore --config config.json --from pact-backup.tar.gz --yes
```

Both are **offline** commands: stop the node first (they refuse while `pact.lock` is
held). `create` takes a consistent SQLite snapshot (`VACUUM INTO`), the `blobs/` tree,
and — by default — `keyring.key`, into one tarball.

**The tarball is the node's data, not a credential.** The snapshot is stripped of every
leaf's private key and then rebuilt, so the keys are in neither its rows nor its free
pages; the ledger of leaves travels as `former` rows. A leaf is the owner's root trusting
*this host* for one address until one date, and a copy of its key would let whoever held
the archive speak as this host. What `keyring.key` still unseals is saved settings and
integration credentials — store the tarball as you would those, or pass
`--without-master-key` and keep the key elsewhere.

`restore` refuses to overwrite an existing store unless `--yes`, unpacks, and prints the
next step (`pact-gateway migrate`, then `serve`). It takes an archive three ways:

| Archive | Flag | Master key | Leaf keys |
|---|---|---|---|
| this node's, restored beside its own `keyring.key` | none | already here | none in the archive |
| this node's, on a fresh machine | `--same-node` | restored | none in the archive |
| another host's | `--data-only` | refused | none in the archive |

In every case the accounts come back **named and not yet served**: contacts, invites,
audit rows and integrations are kept — the audit chain still verifies
(`pact-gateway audit verify`) — and each account waits for a leaf. `serve` names each one
and prints the `account csr` to run; the wallet signs it; `account install-leaf` ends the
wait. Contacts do nothing, because what they pinned is the root.

**Postgres:** the store is external, and `backup create` captures only `blobs/` and
`keyring.key`. A `pg_dump` is a copy of the live database and *does* hold the sealed leaf
keys — it is the operator's, outside this tool. Keep it apart from `keyring.key`, which is
what unseals them.

## Recovery

| Lost | Consequence | Do |
|---|---|---|
| the node, with a backup | accounts are not served until re-certified | restore, `migrate`, `serve`; then one `account csr` / `install-leaf` per account. Contacts keep their pins |
| `keyring.key` only | sealed leaf keys, saved settings and integration credentials are unreadable. **No identity is lost** — the root is in the wallet | put the key back from wherever it was kept |
| one account's leaf key (compromised) | the thief speaks as that host until the leaf expires or is outranked | `pact-gateway account csr --slug me -purpose renew`, have the wallet sign it, `account install-leaf`: the newer leaf outranks the stolen one with every contact it reaches (PACT §14.3) |
| the wallet's root | the identity itself; this node cannot help | the wallet's own recovery, if it has one (PACT §9, §14.5) |
| the audit chain shows a break | someone altered history | `audit verify` names the first bad row; treat the store as untrusted from there |

No telemetry leaves the node, ever; the audit chain is yours alone.

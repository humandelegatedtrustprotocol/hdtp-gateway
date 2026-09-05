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
| nothing inbound at all | relay-assisted: a relay on your card as `X-PACT-GATEWAY` (P4-06/07) | relay-assisted |

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
and — by default — `keyring.key`, into one tarball. **That tarball is your identity:**
whoever holds it holds every account's private key. Store it as you would the node
itself, or pass `--without-master-key` and keep the key elsewhere (a backup without
the key is unreadable until the key is put back).

`restore` refuses to overwrite an existing store unless `--yes`, unpacks, and prints
the next step (`pact-gateway migrate`, then `serve`). Restoring onto a different
machine keeps every contact, invite, key, audit row and integration — the audit chain
still verifies (`pact-gateway audit verify`).

**Postgres:** the store is external; back it up with `pg_dump` and restore with
`psql`. `backup create` still captures `blobs/` and `keyring.key` and tells you to
dump the database separately.

## Recovery

| Lost | Consequence | Do |
|---|---|---|
| the node, with a backup | nothing | restore, `migrate`, `serve`; peers never notice |
| `keyring.key` only | every account's private key is unreadable: **all identities are gone** (SPEC §3.7) | create fresh accounts and re-share cards; there is no recovery ceremony |
| one account's key (compromised) | rotate: `pact-gateway account rotate-key --slug me` — new key, old key live for the grace period, `update_contact` fan-out to every contact; re-run to resume an interrupted fan-out | contacts that missed the rotation re-verify from a fresh card |
| the audit chain shows a break | someone altered history | `audit verify` names the first bad row; treat the store as untrusted from there |

No telemetry leaves the node, ever; the audit chain is yours alone.

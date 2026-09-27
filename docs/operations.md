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

## The store, when it is large

Nothing here needs setting. It is written down so that what the node does to its database is
not a surprise, and so that the one knob that exists is findable.

- **SQLite** (the default) is opened in WAL mode with `synchronous=FULL`, write transactions that
  take their lock at `BEGIN`, and a pool of four connections. Each was measured against a store of
  a million messages and the reasons are beside the code (`internal/core/store/sqlite.go`).
  `synchronous=FULL` is the one that costs speed on purpose: a commit here is a message a peer was
  told was delivered, and it is not given up to a power cut for a faster write.
- **Postgres** (`store_engine: postgres`) uses pgx's pool with its default size, the larger of
  four and the number of CPUs. The DSN is where it changes: append `pool_max_conns=16` (and
  `pool_min_conns`, `pool_max_conn_lifetime`) to `postgres_dsn`.
- **Every hour** the node removes what has outlived its own window, whatever retention an account
  has set: idempotency records of sealed calls, which a node would otherwise keep one of for every
  call it ever took, and owner sessions nobody came back to. With a retention window set it also
  removes the messages, threads and media past it.
- **Every statement the store can run is checked at build time** to have an index on any table
  that grows (`TestEveryQueryHasAPlan`, both engines). To see the numbers on your own hardware:

```
PACT_SCALE_DB=/tmp/pact-scale.db go test ./internal/core/store/ -run '^$' -bench '^BenchmarkScale' -benchtime 20x
```

  The first run seeds the file — 10,000 contacts, a million messages, a million audit rows — and
  takes about a minute. `make scale` runs these benchmarks over a scratch file, and times an import
  of 40,000 threads against one of 10,000 (`PACT_EXPORT_SCALE`), failing if reading or writing it
  grows faster than linearly; the pre-push hook runs `make scale`.

## Export and import

```
pact-gateway export --config config.json --slug alina --out alina.zip
pact-gateway import alina.zip --config config.json --slug alina          # review: writes nothing
pact-gateway import alina.zip --config config.json --slug alina --yes    # writes it
```

Both are **offline** commands: stop the node first (they refuse while `pact.lock` is held).

**An export is one identity's contacts, chats and files, and nothing else** (SPEC §3.10, PACT
§9.2): one unencrypted zip of `manifest.json`, `contacts.csv`, `threads.csv`, `messages.jsonl` and
`media/<sha256>`, the same format the cloud and the `pact` CLI read and write. `export` says, before
it writes, that the file is not encrypted: anyone who gets it can read the contact list and every
conversation and file, though it holds no key and cannot be used to speak as anyone. The file is
created `0600` and never replaces an existing one. A stranger's request that was never accepted,
and its conversation, stay behind.

What is **not** in it, because it is the host's and not the person's: every key, saved settings,
integration credentials, owners, passkeys, sessions, tokens, invites, the audit chain, the ledger
of leaves, and a contact's preset, trust flag and card. There is no flag that adds any of them.

`import` checks the WHOLE file before it writes anything, and refuses it whole at the first fault,
naming the member, row or line. Without `--yes` it shows what it would write and stops. Into a slug
that is not here it creates the identity keyless — its root and nothing more; into the slug the
file belongs to it merges, keeping every pin this host already holds. The rows go in under one
transaction, the files after it. An undelivered outbound message arrives as `failed`: delivering
it was the old host's job, under the old host's leaf.

Every import ends the same way: a request for a new leaf, which the import mints itself — `move`
for an identity that arrived, `renew` for one that was here — and prints with how to complete it
(the portal's `/identity/<slug>/wallet` for the web wallet, or the request itself for the CLI
wallet). Installing the leaf sends every imported contact this host's handshake (`account announce`
reports it). With no `public_url` set there is no address to ask for, and it names `account csr`
instead.

This is not a backup of the node, and the node has none: what a host accumulates beyond contacts
and chats is rebuilt, not restored. After a lost machine: `import`, the setup wizard for a passkey,
reconnect integrations, one certificate per identity.

## Recovery

| Lost | Consequence | Do |
|---|---|---|
| the node, with an export per identity | identities are not served until re-certified; settings, integrations, passkeys and the audit history are not in an export | `import` each, `serve`, the setup wizard; then one `account csr` / `install-leaf` per identity. Contacts keep their pins |
| `keyring.key` only | sealed leaf keys, saved settings and integration credentials are unreadable. **No identity is lost** — the root is in the wallet. If nothing on the node opens under the master key it was given, `serve` refuses to start and says why; if anything does, it starts and prints `NOT SERVED` for each account that does not | put the key back if it was kept anywhere, and nothing is lost. If it is gone for good: `export -slug` each identity, then `import` each into a fresh data directory — an export never needed the master key, because it never held anything sealed under it. For a single `NOT SERVED` account on a running node, a renewal alone does it: the install retires the key it cannot open and says so |
| a leaf simply ran out (nobody renewed it) | the account stops being served within the hour and its key is destroyed; contacts keep their pins, and `doctor` warns before it happens | `account csr --slug me -purpose renew`, the wallet signs, `account install-leaf` |
| one account's leaf key (compromised) | the thief speaks as that host until the leaf expires or is outranked | `pact-gateway account csr --slug me -purpose renew`, have the wallet sign it, `account install-leaf`: the newer leaf outranks the stolen one with every contact it reaches (PACT §14.3) |
| nothing: the person moved an identity to another host | this node goes on serving it, with its key, until told | `pact-gateway account leave -slug me -yes` once the new host has told the contacts (without `-yes` it shows what it would erase): every record and leaf key of the identity erased, its address reserved until its last leaf expires (SPEC.md §3.11) |
| the wallet's root | the identity itself; this node cannot help | the wallet's own recovery, if it has one (PACT §9, §14.5) |
| the audit chain shows a break | someone altered history | `audit verify` names the first bad row; treat the store as untrusted from there |

No telemetry leaves the node, ever; the audit chain is yours alone.

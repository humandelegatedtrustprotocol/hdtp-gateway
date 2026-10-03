# Demo: your own domain — a hdtp-gateway ingress on a VPS

The P5 exit demo: a hdtp-gateway in the **ingress role** on a public VPS holds
`example.com`, and two home nodes sit behind it on subdomains — one in
**passthrough** (raw SNI forwarding, the node's own cert end to end, direct mode) and
one in **terminate** (ACME certificate at the ingress, fresh mutually-pinned mTLS to
the node, edge mode). Both home nodes only ever connect **outbound**.

**Verification status:** the whole path runs in-process in `make check` against an embedded frp
server and an in-process Pebble ACME CA (`internal/integrationtest/ingress_test.go`).
The live VPS run below has **not yet been executed** — `Last manual run: —`.

## What you need

- A VPS with ports **443** (public TLS), **80** (HTTP-01, or use DNS-01) and **7000**
  (frp control plane; restrict to your nodes' IPs or keep the frps token secret)
- `example.com` on Cloudflare DNS (the first DNS adapter) with an API token holding
  `Zone.DNS:Write`
- The static `hdtp-gateway` binary on the VPS and on each home machine

## 1. Ingress on the VPS

```
# HDTP_INGRESS_TOKEN is the data-plane credential paired nodes authenticate the
# frp tunnel with. It is REQUIRED — the ingress refuses to start without it.
export HDTP_INGRESS_TOKEN="$(openssl rand -hex 32)"

HDTP_DATA_DIR=/var/lib/hdtp-ingress hdtp-gateway ingress serve \
  --domain example.com \
  --dns cloudflare --cloudflare-token $CF_TOKEN \
  --acme-email you@example.com \
  --terminate        # omit if every subdomain is passthrough
```

Point `*.example.com` at this host. With `--dns cloudflare` the ingress obtains a
single **wildcard** certificate over DNS-01, which covers every subdomain — it
never writes DNS records itself, so the Cloudflare token needs only the DNS-01
solver's permissions. Without a Cloudflare token it falls back to per-subdomain
HTTP-01, which needs each name to resolve here already and port 80 reachable;
it says which it chose on startup.

Both serving modes share **:443**. The ingress reads each connection's SNI and
either splices it to the data plane untouched (passthrough — it cannot read
that traffic) or terminates it (terminate). Nodes dial `:7000`.

It prints its identity fingerprint — write it down; the home nodes pin it. The key
is kept at `$HDTP_DATA_DIR/ingress.key` and reused on every restart: paired nodes
pin it, so a fresh key would break every pairing.

Mint one pairing token per node:

```
hdtp-gateway ingress token           # → pair_… (single use, 10 min)
```

## 2. Pair a passthrough node (`alice.example.com`)

On Alice's machine, open the portal → *Settings → Ingress* and pair: the
pairing URL, the one-time token, subdomain `alice`, mode **passthrough**, and
the ingress fingerprint you wrote down. Leaving the fingerprint empty trusts
whatever answers and reports the key back for you to check.

Pairing stores the data-plane credentials (sealed with the node's keyring),
selects the `ingress-passthrough` adapter and sets the public URL to
`https://alice.example.com`. Restart the node to serve there. Until a pairing
exists the ingress adapters cannot be selected at all — the node would have no
way to start. The node connects outbound over TLS with its
identity cert, the ingress pins its key, and the answer configures the
`ingress-passthrough` adapter (embedded frp client, SNI `alice.example.com`). The node
derives **direct** mode: `client_cert preferred`, seal as you chose.

Verify from anywhere:

```
openssl s_client -connect alice.example.com:443 -servername alice.example.com -showcerts </dev/null 2>/dev/null \
  | grep -c 'BEGIN CERTIFICATE'
```

Two certificates come back: **Alice's own chain**, her leaf and the root that signed it —
the ingress never touched the TLS session. `hdtp-gateway doctor` on Alice's node validates
that chain the way a peer would, to her root at this address (HDTP §14.2), and reports
`ok probe https://alice.example.com reachable`.

## 3. Pair a terminate node (`bob.example.com`)

Same flow with mode **terminate**. The ingress obtains an ACME certificate for
`bob.example.com` (HTTP-01, or DNS-01 through Cloudflare for wildcards), and Bob's
node gets the `ingress-terminate` adapter: his reverse tunnel serves only the internal
name `bob.internal.example.com`, and his listener accepts **only the ingress's pinned
certificate**. Bob's node derives **edge** mode: `seal required`, `client_cert off`
— callers are identified by their sealed envelopes, because the ingress terminated
their TLS.

```
curl -sv https://bob.example.com/.well-known/hdtp-probe?nonce=1 2>&1 | grep -E "issuer|nonce"
```

shows a public CA issuer (Let's Encrypt) — that is the edge — and the probe echo from
Bob's node behind it.

## 4. What each party can see

| | passthrough (`alice`) | terminate (`bob`) |
|---|---|---|
| public TLS terminated by | Alice's node | the ingress |
| caller's client cert reaches node | yes | no — identity from sealed envelopes |
| ingress can read traffic | no (ciphertext + SNI) | yes, except sealed payloads |
| certificate on the wire | Alice's identity cert (pinned by contacts) | public ACME cert |

Metadata (who talks to whom, sizes, timing) is visible to the ingress in both modes —
the ingress is a trusted edge **you** run (SPEC §13).

## 5. Recovery notes

- Ingress lost: re-provision, re-mint tokens, re-pair. Contacts pin each person's
  root, not the ingress, so nothing needs re-sharing.
- Leaf renewed: `hdtp-gateway account csr -purpose renew`, the wallet signs it,
  `account install-leaf`. Contacts learn the new leaf on their next call
  (`certificate_renewed`, HDTP §14.4). The ingress does not: a renewal makes a fresh
  key, the ingress pinned the old one at pairing, and in terminate mode it refuses the
  node (`node key … is not the one pinned at pairing`) until you pair again with a
  fresh token.

# Demo: reachable through Tailscale Funnel (direct mode, no port forward)

The `tailscale` adapter embeds the official **tsnet** library and asks Tailscale
Funnel for a public TCP stream. The node runs its **own** TLS on that stream, so
callers' client certificates reach the node end to end — this is **direct mode**
(`TerminatesAtEdge=false`): `client_cert` stays `preferred`, `seal` stays owner-chosen
(SPEC §10.1–§10.2). The Funnel relay never decrypts; it does see connection metadata
(SPEC §13).

**Verification status:** configuration plumbing is unit-tested
(`internal/tunnel/tailscale_test.go`). The automated gate cannot run Funnel (it needs a tailnet). The live
run below has **not yet been executed** — record it here when done:
`Last manual run: —`.

## Limits (tsnet, checked 2026-08-24)

- TCP only; **ports 443, 8443 or 10000** — nothing else.
- Hostname is the tsnet node's `*.ts.net` MagicDNS name; you cannot bring your own domain
  (use the `direct`/`frp` adapters or the ingress role for that).
- **Funnel is beta** and Tailscale-hosted; it must be enabled for the tailnet
  (Admin console → DNS → HTTPS certificates + MagicDNS; Access controls → `nodeAttrs`
  granting `funnel`).
- An auth key: reusable, preauthorized, ideally tagged (Admin console → Keys).

## Configure

`config.json` (or env `HDTP_TUNNEL=tailscale`):

```json
{
  "tunnel": "tailscale",
  "public_bind": "127.0.0.1:8443"
}
```

Adapter settings live in the portal (*Settings → Adapter credentials*, stored
encrypted with the node's keyring) or in the environment with an `HDTP_TUNNEL_`
prefix — `HDTP_TUNNEL_AUTH_KEY` reaches the adapter as `auth_key`. The
environment wins where both are set, and the page says so rather than letting
you save a value that would be ignored.

| key | value |
|---|---|
| `hostname` | `hdtp` → public name `hdtp.<tailnet>.ts.net` |
| `auth_key` | the auth key (or set `TS_AUTHKEY` in the environment) |
| `port` | `443` (default), `8443` or `10000` |
| `funnel_only` | `true` to refuse tailnet-internal connections (public only) |
| `state_dir` | where tsnet keeps node state (defaults under the data dir) |

Because the adapter derives **direct** mode, the LAN-connections flag defaults **on**
and carries no security weight here (SPEC §10.1).

## Run and verify

```
hdtp-limitd -config limits.json &   # the limits sidecar (SPEC §5.7): deploy/limitd/limits.json with "socket" set to <data_dir>/limits.sock
hdtp-gateway serve
hdtp-gateway doctor
```

`doctor` prints `ok tunnel tailscale (mode direct, seal required, client_cert preferred)`
and runs the reachability probe against `https://hdtp.<tailnet>.ts.net`, validating the
chain served there to an identity's root at its own address (the node's own listener is
what Funnel forwards to, so a WebPKI check would be wrong). Expect `ok probe … reachable`
with the hairpin caveat.

From another machine on the open internet:

```
openssl s_client -connect hdtp.<tailnet>.ts.net:443 -servername hdtp.<tailnet>.ts.net -showcerts </dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE'
```

Two certificates come back — the node's own chain, a leaf and the root that signed it, not
Tailscale's — proving end-to-end TLS through the Funnel. `hdtp-gateway doctor` validates
that chain the way a peer would (HDTP §14.2).

Then pair from a second node with the invite link — the endpoint the card's leaf names is
`https://hdtp.<tailnet>.ts.net/a/<slug>/mcp`.

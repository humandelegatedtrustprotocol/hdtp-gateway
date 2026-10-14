# Demo: reachable through an ngrok TLS endpoint (direct mode)

The `ngrok` adapter embeds the official **ngrok-go v2** agent and opens a
**`tls://` endpoint**: ngrok forwards the raw TLS stream without terminating it, the
node runs its own TLS, and callers' client certificates reach the node end to end —
**direct mode** (`TerminatesAtEdge=false`, SPEC §10.1–§10.2).

**Paid feature.** TLS endpoints are **not available on ngrok's free plan**; the adapter
is config-gated and refuses to construct without an authtoken; with a free-plan token the node stops
at start with `ERR_NGROK_312` (TLS endpoints are not on the free plan), measured 2026-10-13. For a
free ngrok setup use the `ngrok` compose profile, ngrok's agent as a sidecar with the node in edge
mode ([quickstart § 4](../quickstart.md#4-set-the-address-people-will-reach-you-at)). The built-in
`ngrok-https` edge adapter serves nothing: every request through it is answered `400` [#167](https://github.com/humandelegatedtrustprotocol/hdtp-gateway/issues/167).

**Verification status:** config gating and raw-listener wrapping are unit-tested
(`internal/tunnel/ngrok_test.go`); the live path needs a paid account and has **not
yet been executed** — `Last manual run: —`.

## Configure

```json
{ "tunnel": "ngrok", "public_bind": "127.0.0.1:8443" }
```

| key | value |
|---|---|
| `auth_token` | ngrok authtoken (or env `NGROK_AUTHTOKEN`) |
| `url` | `tls://<reserved-domain>` or `tls://` for an allocated hostname |
| `name` | endpoint name (default `hdtp`) |

`doctor` reports `ok tunnel ngrok (mode direct, …)` and probes
`https://<endpoint>` pinned to the account's identity fingerprint.

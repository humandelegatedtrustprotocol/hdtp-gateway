# Demo: reachable through an ngrok TLS endpoint (direct mode)

The `ngrok` adapter embeds the official **ngrok-go v2** agent and opens a
**`tls://` endpoint**: ngrok forwards the raw TLS stream without terminating it, the
node runs its own TLS, and callers' client certificates reach the node end to end —
**direct mode** (`TerminatesAtEdge=false`, SPEC §10.1–§10.2).

**Paid feature.** TLS endpoints are **not available on ngrok's free plan**; the adapter
is config-gated and refuses to construct without an authtoken. For a free ngrok setup
use the `ngrok-https` **edge** adapter instead (P4-05): ngrok terminates TLS there, the
node derives edge mode, and identity comes from sealed envelopes.

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

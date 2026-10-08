# internal/tunnel

Tunnel adapters and the reachability probe (SPEC.md §10.1, §10.2, §10.4). An adapter changes reachability only: the protocol surface is the same behind any of them. Each adapter declares one boolean, `TerminatesAtEdge`, which the package registers with `core` at init (`core.RegisterTunnel`), and `core.Config.Derive` turns that into direct or edge mode and the forced `seal` / `client_cert` / LAN knobs; the adapter never has to be trusted to say so. Callers: `internal/cli/compose.go` (`startTunnel` builds the named adapter from the configured name, `PublicBind`, `PublicURL` and the `Extra` settings, then starts it), `internal/cli/serve.go`, `internal/cli/doctor.go` and `internal/services/settings/settings.go` (`Probe`, `Names`), `internal/node/node.go` (`SourceIP`, `TrustedClientIPHeader`, `ProbeHandler`) and `internal/public/listener.go` (mounts the probe at `ProbePath`). The adapters wrap off-the-shelf libraries: the frp client, ngrok-go v2, tsnet, and the `cloudflared` binary. The package imports only `internal/core` of the node, plus hdtp-identity for the probe's chain validation.

## What it holds

The contract and registry:
- `Adapter` (`Start`, `Status`, `Stop`), `Info`, `Status`, `Options`: the adapter contract. `Info.Listener` is non-nil for `tailscale` and `ngrok` (a raw stream the node runs its own TLS on) and for `ngrok-https` (a stream of decrypted HTTP); `direct`, `cloudflare` and `frp` (which dials the node's own bind) return none.
- `Register`, `New`, `Names`: the name-to-constructor registry. `New` validates the options in the constructor.

Adapters (name, `TerminatesAtEdge`, `Extra` keys):
- `direct`, false: `Direct`; the node's own bind is the public endpoint; needs `PublicURL`.
- `tailscale`, false: `Tailscale`; tsnet Funnel. Keys `hostname` (required), `auth_key` (or `$TS_AUTHKEY`, required), `state_dir`, `port` (443, 8443 or 10000; default 443), `funnel_only`, `control_url`.
- `frp`, false: `FRP`; the embedded frp client to an owner-run frps. Keys `server_addr` (required), `server_port` (default 7000), `token`, `proxy_type` (`tcp` default, or `https`), `remote_port` (tcp, required), `custom_domain` (https, required), `vhost_https_port` (https; default 443), `name` (default `hdtp`), and any `meta_<k>` as login metadata.
- `ngrok`, false: `Ngrok`; a paid `tls://` endpoint, unterminated. Keys `auth_token` (or `$NGROK_AUTHTOKEN`, required), `url` (default `tls://`), `name` (default `hdtp`).
- `cloudflare`, true: `Cloudflare`; a supervised `cloudflared` child or the compose sidecar. Keys `token` (or `$TUNNEL_TOKEN`), `hostname`, `binary`, `sidecar`.
- `ngrok-https`, true: `NgrokHTTPS`; the free HTTPS endpoint, ngrok terminates TLS. Keys `auth_token` (or `$NGROK_AUTHTOKEN`), `url` (must be `https://`; default `https://`), `name`.
- `ingress-passthrough` (false) and `ingress-terminate` (true): the frp adapter configured from an ingress pairing (SPEC.md §10.6). Keys `subdomain`, `domain`, `data_plane_addr`, `node_fpr`, `node_secret` (all required) and `data_plane_port` (default 7000), `data_plane_token`. Passthrough tunnels `<sub>.<domain>`, terminate tunnels `<sub>.internal.<domain>`; both log in with the node fingerprint and secret as frp metadata. Their `Status` reports the name `frp`.

Edge helpers: `TrustedClientIPHeader`, `SourceIP`, `ComposeSidecar`.

Probe (SPEC.md §10.4): `ProbePath`, `ProbeHandler`, `Probe`, `ProbeOptions`, `Served`, `Result`, `Verdict` and its four values.

## What it refuses, and how

- Constructors return errors before any network is touched: `direct` without `PublicURL`; `tailscale` without `hostname` or an auth key, or with a port outside 443/8443/10000; `frp` without `server_addr`, with a port outside 1..65535, with a `proxy_type` other than `tcp`/`https`, a tcp proxy without `remote_port`, an https proxy without `custom_domain`, or a `PublicBind` that is not `host:port`; `ngrok` without a token or with a `url` that is not `tls://`; `ngrok-https` without a token or with a `url` that is not `https://`; `cloudflare` without a tunnel token or a hostname; the ingress adapters without any of their required keys. `New` of an unknown name lists the registered ones.
- Source address (SPEC.md §5.7): `SourceIP` takes the client address from a header only when the adapter terminates at an edge and has a trusted header; only `cloudflare` has one (`CF-Connecting-IP`). `X-Forwarded-For` is never read; with no trusted header the socket address is used.
- Probe verdicts: `unreachable` (not a URL, or a transport failure that is not a certificate failure), `wrong_cert` (a TLS or x509 failure, or, when identities are given, a chain that is not exactly two certificates or does not validate to one of the served roots at its own address), `wrong_instance` (a non-200, an answer without the nonce, or another instance id), else `reachable`. A `SelfOriginated` probe carries a hairpin caveat on every verdict.
- Network rules of the probe: it dials the endpoint it is given (`DialContext` can replace the dialer) with a 10 second timeout unless `Timeout` is set, uses TLS 1.2 or later, sends a fresh 16-byte random nonce, and reads at most 4096 bytes of the answer. `ProbeHandler` cuts the echoed nonce to 64 bytes. This package does not refuse inward (private or loopback) addresses and does not set a redirect policy: the HTTP client uses net/http's default. The endpoint it probes is the node's own configured public URL.
- Other constants: `frp.Stop` gives in-flight work connections 2 seconds (`GracefulClose`) and waits up to 5 seconds for the client to return; `cloudflared` is run with only `PATH` and `HOME` in its environment.

## Invariants

- Registering an adapter registers its edge flag with `core` once, at the same call (`Register`); nothing else holds the flag.
- The edge adapters force `seal: required`, `client_cert: off` and LAN off through config resolution, whatever the owner configured (`TestEdgeAdaptersDeriveEdgeMode`).
- The probe judges a node the way a peer does: by the chain and the address dialled, not by a key fingerprint. A leaf naming another address fails with the rule number in `Detail`.
- A tunnel token is never written into the compose snippet; `ComposeSidecar` shows `${TUNNEL_TOKEN}`.
- The frp client is stopped before its context is released, so `Stop` returns only after `Run` has.

## Held by

- `edge_test.go`: `TestEdgeAdaptersDeriveEdgeMode`, `TestCloudflareOptionsAndSidecarFallback`, `TestCloudflareSpawnsTheConnector`, `TestNgrokHTTPSIsEdgeAndRefusesTLSURL`, `TestSourceIPHonorsOnlyTheAdaptersTrustedHeader` (including that `X-Forwarded-For` is never the answer).
- `frp_test.go`: `TestFRPOptionsPlumbing`, `TestFRPPassthroughKeepsClientCertVisible`, `TestFRPCallersDuringRegistrationAreServed`, `TestFRPStopRightAfterStart` (Stop returns with `Run` finished).
- `ingress_test.go`: `TestIngressAdaptersDeriveModes` (passthrough derives direct, terminate derives edge with seal required and client cert off; pairing data is mandatory; the terminate adapter tunnels the internal name).
- `ngrok_test.go`: `TestNgrokIsConfigGated`, `TestNgrokWrapsRawListenerForNodeTLS`. `tailscale_test.go`: `TestTailscaleOptionsPlumbing`, `TestTailscaleIsRegisteredAsDirectMode`.
- `probe_test.go`: `TestProbeVerdicts`, `TestProbeRefusesALeafThatNamesAnotherAddress`, `TestProbeRefusesALoneSelfSignedCertificate`.
- The tsnet, ngrok and cloudflared network paths themselves are not exercised by these tests: they are reached through injected listeners and spawners.

## What it does not do

- It does not make a node reachable by itself in `direct`: the owner supplies the port forward or address.
- There is no relay role and no store-and-forward here (SPEC.md §10.1).
- It does not validate a caller or open an envelope. In edge mode the identity of a caller rests on sealed envelopes; this package only reports `TerminatesAtEdge`.
- The probe is not a pass/fail oracle behind NAT: a hairpin probe is reported with a caveat, not as a clean pass.
- `ingress-terminate` reports the internal name as its public URL; the ingress, not this package, fronts the public name.

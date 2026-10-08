# internal/ingress

The ingress role (SPEC.md §10.6): a public front door that holds DNS and certificates for a domain and fronts paired nodes on subdomains, in one of two modes. The package is called by `internal/cli/ingresscmd.go`, which builds the registry, the data plane, the ACME manager, the terminator, the front door and the pairing server for `hdtp-gateway ingress`; by `internal/services/settings/ingresspair.go`, which runs `Pair` for the node side; and by `internal/node/node.go`, whose `TLSConfig` calls `PinOnwardLeg` when the node has an ingress fingerprint. It calls certmagic (ACME), the embedded frp server (data plane), `internal/identity` (fingerprints), and nothing else of the node; the DNS-01 provider is supplied by `internal/ingress/dns`. The pairing and registry protocol is meant to be the one a hosted platform would speak (SPEC.md §10.6).

## What it holds

Registry and pairing:
- `Mode` (`ModePassthrough`, `ModeTerminate`), `Node`, `Registry`, `NewMemoryRegistry`, `NewFileRegistry`: the book of paired nodes and single-use pairing tokens; the file registry persists nodes (never tokens) as JSON.
- `ValidSubdomain`, `InternalName`: one DNS label; and `<sub>.internal.<domain>`, the name a terminate-mode node's reverse tunnel registers.
- `PairingServer` (`Handler`, `OnPaired`), `PairRequest`, `PairResponse`, `Pair`, `PairError`: the pairing endpoint and its node-side client.

Routing:
- `FrontDoor`: accepts on the public port, reads one ClientHello, routes by SNI to passthrough (a splice to the data plane) or terminate (a `ConnSink`).
- `ConnSink`, `ChanListener`, `NewChanListener`: the hand-off from the front door to the terminator, as a `net.Listener` whose `Deliver` can give up.
- `DataPlane` (`Start`, `Stop`), `MetaNode`, `MetaSecret`: the embedded frps and its registry-enforcing plugin.

Terminate mode:
- `ACME`, `ACMEOptions`, `NewACME`, `Manage`, `TLSConfig`, `Close`: certmagic with its own cache; HTTP-01 for single names, DNS-01 when a provider is set.
- `Terminator` (`Serve`, `DialNode`, `Close`): terminates the public TLS session and pipes to the node over a fresh mTLS leg that must present the SPKI pinned at pairing.
- `PinOnwardLeg`: the node side of that leg; makes a `tls.Config` require a client certificate and accept only the paired ingress's.

## What it refuses, and how

Pairing (`PairingServer.Handler`, `POST /pair`, JSON codes in the body):

| Status | Code | When |
|---|---|---|
| 401 | `identity_required` | no client certificate, or its key has no identity fingerprint |
| 400 | `bad_request` | the body does not decode as JSON within its first 4096 bytes; invalid subdomain; mode not `passthrough`/`terminate` |
| 403 | `invite_invalid` | token unknown, already used or expired (audited `ingress_pair` / `invite_invalid`) |
| 409 | `conflict` | `Registry.Put` refused, e.g. the subdomain is paired to another fingerprint |

The route is registered as `POST /pair`: another method on `/pair` is the mux's 405, any other path its 404.

The token is consumed before `Put`, so a conflict spends it. `Pair` returns `*PairError` for any non-200, and aborts the handshake before sending when the served certificate's fingerprint differs from the one it was given; with an empty expected fingerprint it trusts on first use and returns the fingerprint it saw. The chain is never validated.

Front door (closes the connection without a reply; audit action `ingress_route`): `bad_hello` (not a TLS handshake record, a record over 16384 bytes, a malformed ClientHello, no SNI, or no hello within 10 seconds), `not_our_domain`, `unpaired`, `terminate_not_configured`, `terminate_unavailable` (the terminator did not take the connection within 5 seconds), `unreachable` (the data plane could not be dialled; the dial timeout is `DialTimeout`, default 10 seconds). An unpaired name is dropped, never answered, so it does not reveal whether it exists.

Data plane plugin: `Login` is rejected unless the metadata names a paired fingerprint and carries that node's secret; `NewProxy` is rejected unless it is one `https` proxy with exactly one custom domain equal (case-insensitively) to `<sub>.<domain>` (passthrough) or `<sub>.internal.<domain>` (terminate). The vhost (SNI-routed) port binds `127.0.0.1` unless `ProxyBindAddr` is set; the control port binds `BindAddr`.

Terminator: `DialNode` fails if the node serves no certificate or a certificate whose PKIX public key is not byte-equal to `Node.SPKI`. A connection that fails the public handshake, has an SNI outside the domain, or names an unpaired or non-terminate subdomain is closed (`ingress_terminate` / `unknown`); a failed onward dial is closed as `unavailable`.

Constants: `helloTimeout` 10 s, `handoffTimeout` 5 s, ACME `CertObtainTimeout` 2 minutes, default dial timeouts 10 s, `Pair`'s default client timeout 15 s, TLS 1.2 minimum on the public config and both mTLS legs. The public TLS config offers ALPN `http/1.1` first and no `h2`.

## Invariants

- The front door never terminates TLS; a passthrough connection reaches the data plane with the ClientHello bytes it sent.
- A pairing token buys exactly one pairing attempt.
- The file registry writes before it reports success, atomically (temporary file renamed), mode 0600; tokens are never written to disk.
- The vhost defaults to loopback, so a caller cannot reach it and skip the registry lookup.
- The onward leg accepts only the key pinned at pairing; `PinOnwardLeg` is the pin the node's listener ships with, and only checks the transport (it does not make the ingress a caller).
- Handing a connection to the terminator can give up (`ConnSink.Deliver` takes a timeout), so a stopped terminator does not park public connections.

## Held by

- `ingress_test.go`: `TestPairingTokenIsSingleUse` (wrong pin aborts, token reuse and unknown tokens refused, no-cert pairing is 401, a second node cannot take a paired subdomain); `TestSNIPassthroughRoutesAndKeepsClientCertVisible`; `TestTerminatePairingAnnouncesItsNameForACertificate` (`OnPaired` fires for terminate only); `TestDataPlaneStopRightAfterStart`.
- `fileregistry_test.go`: `TestPairingsSurviveARestart` (round trip, file not readable by others, tokens not persisted).
- `frontdoor_test.go`: `TestOnePortRoutesPassthroughAndTerminateBySNI`; `TestFrontDoorRefusesNonTLS` (calls `peekSNI` on plain HTTP); `TestFrontDoorDropsWhenTheTerminatorIsNotAccepting`; `TestDataPlaneVhostDefaultsToLoopback`.
- `terminate_test.go`: `TestACMEIssuanceAndRenewalWithPebble`; `TestTerminateModeRoundTripsSealedCallAndRefusesUnpinnedNode` (a sealed call round-trips; `DialNode` refuses a node whose key is not the pinned one; the node refuses a non-ingress client); `TestTerminatePublicTLSAcceptsAClientThatOffersALPN`.
- The layering rule `TestImportsPointDownTheLayers` in `internal/integrationtest`.

## What it does not do

- It does not write DNS records per pairing. The wildcard is pointed at the ingress once; the optional `internal/ingress/dns` adapter only answers DNS-01.
- It holds no certificate for a passthrough subdomain; the command calls `Manage` for the wildcard `*.<domain>` (when a Cloudflare token is set and the wildcard is obtained) or for each terminate-mode name, never for a passthrough one.
- It does not authenticate a caller or open an envelope. In terminate mode the ingress can read traffic apart from sealed payloads; caller identity comes from the sealed envelope (SPEC.md §10.6).
- The pairing tokens are in memory: a restart forgets outstanding ones, and `ingress token` mints a new one.
- `Registry.Put` keys on the subdomain: the same fingerprint may re-pair on the same subdomain, and it replaces the row. A node can hold more than one subdomain; `ByFingerprint` returns only one of them.

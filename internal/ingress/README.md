# internal/ingress

The ingress role (SPEC.md §10.6): a public front door that holds DNS and certificates for a domain and fronts paired nodes on subdomains, in one of two modes. The package is called by `internal/cli/ingresscmd.go`, which builds the registry, the data plane, the ACME manager, the terminator, the front door and the pairing server for `hdtp-gateway ingress`; by `internal/services/settings/ingresspair.go`, which runs `Pair` for the node side; and by `internal/node/node.go`, whose `TLSConfig` calls `PinOnwardLeg` when the node has an ingress fingerprint. It calls certmagic (ACME), the embedded frp server (data plane), `internal/identity` (fingerprints), and nothing else of the node; the DNS-01 provider is supplied by `internal/ingress/dns`. The pairing and registry protocol is meant to be the one a hosted platform would speak (SPEC.md §10.6).

## What it holds

Registry and pairing:
- `Mode` (`ModePassthrough`, `ModeTerminate`), `Node`, `Registry`, `NewMemoryRegistry`, `NewFileRegistry`: the book of paired nodes and single-use pairing tokens; the file registry persists nodes (never tokens) as JSON. `Registry.ByCredential(fpr, secret)` is the data plane's lookup (the secret compared in constant time; an empty one matches nothing); `Registry.Remove(sub)` forgets a pairing (`ErrNotPaired` when none holds it).
- `ValidSubdomain`, `InternalName`: one DNS label; and `<sub>.internal.<domain>`, the name a terminate-mode node's reverse tunnel registers.
- `PairingServer` (`Handler`, `OnPaired`), `PairRequest`, `PairResponse`, `Pair`, `PairError`, `ErrIngressPin`: the pairing endpoint and its node-side client; `ErrSubdomainTaken`, `Put`'s refusal of a subdomain paired to another fingerprint.

Routing:
- `FrontDoor`: accepts on the public port, reads one ClientHello, routes by SNI to passthrough (a splice to the data plane) or terminate (a `ConnSink`).
- `ConnSink`, `ChanListener`, `NewChanListener`: the hand-off from the front door to the terminator, as a `net.Listener` whose `Deliver` can give up.
- `DataPlane` (`Start`, `Stop`, `Unpair`), `MetaNode`, `MetaSecret`: the embedded frps and its registry-enforcing plugin. `Unpair(sub)` is what `ingress unpair` calls over the admin socket: `Registry.Remove`, then frps closes every live session whose login credentials the registry no longer accepts (`CloseControls`, added to the vendored frp by `third_party/frp.patch`), and `Unpair` returns once their proxies are closed.

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
| 409 | `conflict` | the subdomain is paired to another fingerprint (`ErrSubdomainTaken`; audited `refused`) |
| 503 | `unavailable` | the registry could not record the pairing (the file registry's write failed; audited `error`) |

Every refusal's body is a JSON object holding the code alone (`{"code":"conflict"}`), served as `application/json`.

The route is registered as `POST /pair`: another method on `/pair` is the mux's 405, any other path its 404.

The token is consumed before `Put`, so a conflict spends it. `Pair` returns `*PairError` for any non-200, and aborts the handshake before sending when the served certificate's fingerprint differs from the one it was given; with an empty expected fingerprint it trusts on first use and returns the fingerprint it saw. The chain is never validated.

Front door (closes the connection without a reply; audit action `ingress_route`): `bad_hello` (not a TLS handshake record, a record over 16384 bytes, a malformed ClientHello, no SNI, or no hello within 10 seconds), `not_our_domain`, `unpaired`, `terminate_not_configured`, `terminate_unavailable` (the terminator did not take the connection within 5 seconds), `unreachable` (the data plane could not be dialled; the dial timeout is `DialTimeout`, default 10 seconds). An unpaired name is dropped, never answered, so it does not reveal whether it exists.

Data plane plugin: `Login` is rejected unless the metadata names a paired fingerprint and carries the secret of one of its pairings (`ByCredential`), and the node is then known as that pairing; `NewProxy` is rejected unless it is one `https` proxy with exactly one custom domain equal (case-insensitively) to `<sub>.<domain>` (passthrough) or `<sub>.internal.<domain>` (terminate). The vhost (SNI-routed) port binds `127.0.0.1` unless `ProxyBindAddr` is set; the control port binds `BindAddr`.

Terminator: `DialNode` fails if the node serves no certificate or a certificate whose PKIX public key is not byte-equal to `Node.SPKI`. A connection that fails the public handshake or has an SNI outside the domain is closed silently, with no audit row; one naming an unpaired or non-terminate subdomain is closed and audited `ingress_terminate` / `unknown`; a failed onward dial is closed and audited `unavailable`.

Constants: `helloTimeout` 10 s, `handoffTimeout` 5 s, ACME `CertObtainTimeout` 2 minutes, default dial timeouts 10 s, `Pair`'s default client timeout 15 s, TLS 1.2 minimum on the public config (`ACME.TLSConfig`) and on the two mTLS legs this package builds (`Pair`, `DialNode`); the pairing listener's minimum is set in `internal/cli/ingresscmd.go`, not here. The public TLS config offers ALPN `http/1.1` first and no `h2`.

## Invariants

- The front door never terminates TLS; a passthrough connection reaches the data plane with the ClientHello bytes it sent.
- A pairing token is consumed by the first request that reaches `ConsumeToken`: an unknown or used token (403), a registry conflict (409), a failed write (503) and a success all spend it; a request refused earlier (401 without a client certificate, 400 for a bad body, subdomain or mode) does not.
- The file registry checks a pairing, writes the book with it, and only then changes the book in memory, so a write that fails leaves nothing routed that the next start would not know; the write is atomic (temporary file renamed), mode 0600; tokens are never written to disk.
- The vhost defaults to loopback, so a caller cannot reach it and skip the registry lookup.
- The onward leg accepts only the key pinned at pairing; `PinOnwardLeg` is the pin the node's listener ships with, and only checks the transport (it does not make the ingress a caller).
- Handing a connection to the terminator can give up (`ConnSink.Deliver` takes a timeout), so a stopped terminator does not park public connections.

## Held by

- `ingress_test.go`: `TestPairingTokenIsSingleUse` (wrong pin aborts, token reuse and unknown tokens refused, no-cert pairing is 401, a second node cannot take a paired subdomain); `TestATakenSubdomainIsRefusedWithAJSONBodyHoldingTheCode`; `TestSNIPassthroughRoutesAndKeepsClientCertVisible`; `TestTerminatePairingAnnouncesItsNameForACertificate` (`PairingServer` calls `OnPaired` after every pairing it records; the test's callback keeps only the terminate-mode ones, and holds that the terminate pairing is announced and the passthrough one is not asked for a certificate); `TestDataPlaneStopRightAfterStart`.
- `unpair_test.go`: `TestAnUnpairedNodeLosesItsRouteToTheNextPairing` (real frps and frpc: right after `Unpair` frps no longer holds the old node's session, which it removes only after closing its proxies, and no dial reaches the old node; a node paired on another name keeps its session, and the node paired on the name next is the only one reached).
- `ingress_test.go`: `TestANodePairedTwiceIsKnownByTheSecretItPresents` (two pairings of one fingerprint: each secret resolves its own, 400 of 400; a wrong, an empty and a removed secret are refused).
- `fileregistry_test.go`: `TestARemovedPairingStaysRemovedAcrossARestart` (a removal is written before it is forgotten in memory, and survives a restart); `TestPairingsSurviveARestart` (round trip, file not readable by others, tokens not persisted); `TestAPairingThatCannotBeWrittenIsRefusedAndNotRouted` (an unwritable book is 503 and the pairing is not routed; a refused takeover leaves a book the next start loads).
- `frontdoor_test.go`: `TestOnePortRoutesPassthroughAndTerminateBySNI`; `TestFrontDoorRefusesNonTLS` (calls `peekSNI` on plain HTTP); `TestFrontDoorDropsWhenTheTerminatorIsNotAccepting`; `TestDataPlaneVhostDefaultsToLoopback`.
- `terminate_test.go`: `TestACMEIssuanceAndRenewalWithPebble`; `TestTerminateModeRoundTripsSealedCallAndRefusesUnpinnedNode` (a sealed call round-trips; `DialNode` refuses a node whose key is not the pinned one; the node refuses a non-ingress client); `TestTerminatePublicTLSAcceptsAClientThatOffersALPN`.
- The layering rule `TestImportsPointDownTheLayers` in `internal/integrationtest`.

## What it does not do

- It does not write DNS records per pairing. The wildcard is pointed at the ingress once; the optional `internal/ingress/dns` adapter only answers DNS-01.
- It holds no certificate for a passthrough subdomain; the command calls `Manage` for the wildcard `*.<domain>` (when a Cloudflare token is set and the wildcard is obtained) or for each terminate-mode name, never for a passthrough one.
- It does not authenticate a caller or open an envelope. In terminate mode the ingress can read traffic apart from sealed payloads; caller identity comes from the sealed envelope (SPEC.md §10.6).
- The pairing tokens are in memory: a restart forgets outstanding ones, and `ingress token` mints a new one.
- `Registry.Put` keys on the subdomain: the same fingerprint may re-pair on the same subdomain, and it replaces the row. A node can hold more than one subdomain, each with its own secret.
- `Registry.Remove` alone does not close a data-plane session the node already opened; `DataPlane.Unpair` does. The plugin checks credentials at `Login` and `NewProxy` only (frps calls it for no other operation), so a session `Unpair` did not close would keep its proxy, and with it the vhost route for the name, until it reconnected.

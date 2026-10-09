# internal/outbound

Calls from this node's accounts to their contacts (SPEC.md §10.3, and §4 for the seal policy it applies outbound). It is the one place that decides how a call leaves: whether it is sealed, to which key, with the chain or with a fingerprint, and how the server it reaches is recognised. `internal/node` builds a `Client` per account (`node/outbound.go`, `wireClient`) and wires its hooks to the store, the clock and the node's outbound budget; `internal/cli/contactinit.go` and `node/outbound.go` build the `Peer` from a card or a stored contact. The package speaks MCP through the go-sdk client and seals with hdtp-identity (`SealRequest`, `OpenResult`, `FollowRenewed`, `ValidateChain`); the wire format and the order of the checks are HDTP §13 and §14, not restated here.

## What it holds

- `Peer`: what the client needs of a contact: `Endpoint` (the address the pinned leaf names), `Seal` (`none`, `optional`, `required`, or `""` for none), `Root` (the pinned root's fingerprint, the identity), `Leaf` (the latest accepted leaf, whose key calls are sealed to and answers verified under), `ChainSeen` (the contact has already seen our current leaf, so the call carries the fingerprint, not the chain). `Peer.Known` is true when both a root and a leaf are held.
- `Client`: the account's keypair and TLS certificate, plus hooks: `Roots`, `Now`, `DialContext`, `OnChainSent`, `OnRepin`, `Budget`.
- `Client.Call`: the seal decision and the usual entry point. A peer whose card says `required` or `optional` is sealed to (`SealedCall`); only `none` (or `""`) gets plaintext (`CallTool`).
- `Client.SealedCall`, `Client.SealedListTools`: a `tools/call` or `tools/list` inside an envelope sealed to the peer's leaf key, through the peer's `sealed_call`.
- `Client.CallTool`, `Client.ListTools`: unsealed MCP calls. `CallOptions.Plaintext` marks a call that must be refused against a `required` peer.
- `Client.HTTPClient`: an `http.Client` that dials a peer under the server-validation rules below.
- `ErrSealRequired`, `RateLimited`: the two errors callers match on.

## What it refuses, and how

- `ErrSealRequired` (`seal_required`): `CallTool` with `Plaintext` set against a `required` peer; nothing is sent.
- `RateLimited` (`rate_limited: …`): the hook `Client.Budget` refused; `RetryAfter` is how long until it holds a call again. Every call out passes `Budget` once, before anything leaves the host (`CallTool`, `ListTools`, and the sealed exchange, which `Call` and `SealedCall` reach through). Any other error from `Budget` also stops the call. With no `Budget`, nothing is charged.
- No peer to seal to: a sealed call to a peer with no root or no leaf, or from an account whose keypair has no chain, fails with an error before sending, naming the peer.
- A leaf that does not parse, or whose key cannot be used, fails the attempt with an error before sending.
- Server validation (HDTP §2, SPEC.md §10.3): TLS 1.2 or later; the client certificate is offered unconditionally through `GetClientCertificate`, even when the server's CertificateRequest lists CAs it cannot satisfy. The server is accepted if it presents exactly two certificates (leaf, root) that `ValidateChain` accepts for the pinned root at `Peer.Endpoint`; otherwise only if its certificate is WebPKI-valid for the endpoint's hostname against `Roots` (nil means the system roots; `internal/node` leaves it nil, and a test forbids an empty pool). A lone self-signed certificate is neither, so it is refused, with the same words whether or not a pin is held. HTTP requests time out after 30 seconds.
- Plaintext refusals to a sealed call: only the codes decided before an envelope can open (`chain_required`, `certificate_renewed`, `envelope_invalid`, `seal_required`, `seal_not_accepted`, `identity_required`, `rate_limited`, `unavailable`, `bad_request`, `too_large`) are accepted as the peer's answer. Any other code arriving in plaintext (for example `permission_denied`) fails the call as not attributable to the peer (HDTP §13.2: past the open, the answer is sealed).
- Answers that cannot be verified under any leaf held for the peer fail: against a `required` peer at once, with nothing more sent and an error that says the pin stands; against a peer that takes plaintext, after one plaintext `get_card` and, when its chain is followed, one retry (below).

Follow-ups, each at most once per call (HDTP §13.2, §14.3, §14.4): `chain_required` is answered by resending with the chain when the first attempt carried the fingerprint; `certificate_renewed` is followed only if `FollowRenewed` accepts the chain it carries (to the pinned root, at the dialled address, moving forward), after which the pin moves (`OnRepin`) and the call is re-sealed; an unverifiable answer from a peer that takes plaintext (`optional`) triggers a plaintext `get_card`, whose chain is followed the same way, then a re-pin and one retry. A `required` peer is not asked: a plaintext `get_card` to it is refused unread, and a sealed one would be answered in the form that just failed (the form is the peer's record of what we have seen, not the tool's), so the call fails and the pin stands until an answer from that peer carries the chain — its first after a renewal — or the key sealed to is retired and it answers `certificate_renewed`. Envelopes are dated by `Now` and expire five minutes after sealing. When an envelope carried the chain, `OnChainSent` is called.

## Invariants

- One home for the seal decision: `Call`.
- Sealing to the leaf the peer is held under; the key is read from `Peer.Leaf`, never passed beside it.
- Every call out spends the budget once, before any dial; a refused spend dials nothing.
- An answer is opened against the pin (`Pin{Root, Endpoint, Leaf, State: "active"}`); a newer leaf riding in a result re-pins through `OnRepin`.
- A forged plaintext refusal is never reported as the peer's word.

## Held by

- `budget_test.go`: `TestEveryCallOutPassesTheBudgetOnceAndARefusalDialsNothing`.
- `client_test.go`: `TestClientCertSentDespiteCAList`, `TestASelfSignedServerCertificateIsNotAnIdentity`, `TestWebPKIPathWithInjectedRoots`, `TestPlaintextRefusedToSealRequiredPeer`.
- `seal_test.go`: `TestChainAsServerCertificateValidatesToThePinnedRoot` (accepts the pinned root's chain at its address; refuses another root, another address, a pin that names a leaf key), `TestClientPresentsItsChain`.
- `plaintexterr_test.go`: `TestAPlaintextRefusalPastTheOpenIsNotThePeersAnswer`.
- `unverifiable_test.go`, against a peer that has renewed and answers under a leaf the caller never pinned: `TestAnUnverifiableAnswerFromARequiredPeerIsNotFollowedByAPlaintextGetCard` (no `get_card` reaches the peer, no retry, no re-pin, and the error names the standing pin rather than a refusal), `TestAnUnverifiableAnswerFromAnOptionalPeerIsFollowedByOnePlaintextGetCard` (one `get_card`, one re-pin to its chain's leaf, one retry that returns the result), `TestAnAnswerCarryingTheRenewedChainRepinsWithoutGetCard` (the control: a chain-form answer re-pins as it passes).
- `webpki_test.go`: `TestProductionNeverBuildsAnEmptyRootPool` (source-level check that no production caller builds `Roots: x509.NewCertPool()`).
- The `chain_required` and `certificate_renewed` follow-ups have no test in this directory; `internal/node`'s `TestExitDemo` drives a `certificate_renewed` follow-up end to end.

## What it does not do

- It does not decide who may be called or what a contact's tier is; the node chooses the peer and charges the budget (`Budget`).
- `CallTool` does not seal, whatever `CallOptions` says; sealing is `Call` or `SealedCall`.
- It does not store pins, contacts or audit rows; `OnRepin` and `OnChainSent` tell the host, which does (`node/outbound.go`).
- It does not refuse inward (private or loopback) addresses, set a redirect policy of its own, or bound the size of an answer; the endpoint is a contact's pinned address and `DialContext` can replace the dialer (tests use it to map hosts onto local listeners).
- It does not retry beyond the single follow-ups above, and does not follow a renewal backwards or to another root.

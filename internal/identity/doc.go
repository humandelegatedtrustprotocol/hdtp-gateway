// Package identity holds what this host has of an account's identity (SPEC §3, HDTP §2): the
// account's keypair — P-256 default, Ed25519 permitted — and, once a wallet has certified it,
// the leaf and the root above it. The identity is the root, whose key this node never holds;
// the key here presents the chain as its TLS certificate and signs sealed envelopes.
//
// The package covers account creation and key sealing (Manager), the leaf ledger and its
// transitions — certificate signing requests, installing a wallet's answer, retiring expired keys
// (leaf.go, walletreq.go) — the move campaign that tells contacts of a new address (fanout.go),
// erasing an identity from the host (leave.go), and owner-to-account membership (membership.go).
// See README.md.
package identity

// Package core is the node's foundation below every other package: its configuration and the
// layers that resolve it (SPEC §12.2), the keyring that seals secrets at rest (SPEC §3.7), the
// data-dir lock (SPEC §12.1), the admin unix socket the CLI reaches a running node through, the
// text redaction applied before text from elsewhere is written down, and a few names the other
// packages share (NodeTag, ProcessName, ReservedToolNames).
//
// The store, the audit chain and the authorization policy are not here but in the packages below
// it: core/store, core/audit and core/policy.
package core

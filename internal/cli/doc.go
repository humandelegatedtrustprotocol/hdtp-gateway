// Package cli is the hdtp-gateway binary's whole behaviour: Run dispatches the command line of
// SPEC §12.1 (stdlib flag parsing, one subcommand per concern), and the serving composition of
// SPEC §2.2 lives here too — `serve` opens the store and keyring, starts the tunnel adapter, the
// node, the admin socket and the internal surface (portal and owner MCP), and joins its background
// work before it closes the store.
//
// Commands that act on a node that is running (account, passkey, token, ingress token) are admin
// socket clients: they send a named call over the unix socket under the data directory
// (core.AdminCall) and `serve` answers from handlers it registered (serve_admin.go). Commands that
// read or write the store directly (migrate, audit, export, import) take the data directory's
// lock and so refuse to run while a node is serving. `check store` takes no lock and writes
// nothing; `doctor` takes the lock only to learn whether a node holds it, and releases it at once.
// The package is ranked above every other package of the node (internal/integrationtest/
// layering_test.go), and only cmd/hdtp-gateway ranks above it.
package cli

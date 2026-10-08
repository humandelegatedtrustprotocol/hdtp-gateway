// Package internalui is the node's owner-facing HTTP surface (SPEC §8): the portal API that the
// embedded React app (web/) talks to, the passkey ceremonies and session gate in front of it,
// and the few pages the node renders itself (the web-wallet pages, the OAuth "close this tab"
// page, the public invite landing).
//
// It is built by internal/cli (compose.go, serve.go), which hands each page group its
// dependencies as a *Deps struct and registers the group with a Mount* function on one
// http.ServeMux; HandlerWithAuth then wraps that mux in account resolution, the CSRF check, the
// session gate and the security headers, in that order from the inside out. Sub-packages:
// internalui/auth holds the passkey service and bearer tokens, internalui/ownermcp the owner's
// MCP server, which is mounted beside this handler at /owner/mcp and is not behind its session
// or CSRF layers.
//
// What the pages show or change lives behind the store and the callbacks in the Deps structs; a
// nil callback changes what its route does (hides the control, answers 404, 503 or 400), as each
// Deps field says.
package internalui

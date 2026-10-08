// Package internalui is the node's owner-facing HTTP surface (SPEC §8): the portal API that the
// embedded React app (web/) talks to, the passkey ceremonies and session gate in front of it,
// and the few pages the node renders itself (the web-wallet pages, the OAuth "close this tab"
// page, the public invite landing).
//
// It is built by internal/cli (compose.go, serve.go), which hands each page group its
// dependencies as a *Deps struct and wraps the group's Mount* call in a closure. An outer
// http.ServeMux holds GET /healthz (Health), /owner/mcp and "/", where "/" is HandlerWithAuth:
// it creates the portal's own mux, applies the closures to it, and wraps it in account
// resolution, the CSRF check, the session gate and the security headers, in that order from the
// inside out. Sub-packages: internalui/auth holds the passkey service and bearer tokens,
// internalui/ownermcp the owner's MCP server. /healthz and /owner/mcp never pass this
// package's session, CSRF or account layers.
//
// What the pages show or change lives behind the store and the callbacks in the Deps structs.
// What a nil callback does is stated on each field: some hide a control or leave a route
// unregistered, some change the route's answer (404, 409, 503, 400), and some are called without a
// nil check.
package internalui

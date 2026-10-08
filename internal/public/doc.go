// Package public is the node's HDTP-facing surface (SPEC.md §5): what contacts and guests call.
//
// A request passes, in order: the connection cap (ConnCap) and the LAN guard (LANGuard) around the
// listener; the body cap (CapBody); the route shell and transport facts (Server: the client chain
// the connection proved, the source address); a per-caller MCP server composed from a registry of
// tools (Pool, Registry, Entry) holding exactly what policy.Allow grants that caller's tier, with
// policy re-checked at call time; and the handler (BuiltinEntries, or an integration's tool). A
// `sealed_call` (SealedEntries) carries an HDTP envelope: Identifier opens and decides it with
// hdtp-identity's Decide, applies the effects it returns, and Pool.Dispatch runs the inner request
// against the proven caller's surface; the answer is sealed back. Each refusal has an HDTP §12 code
// (Code) and an audit row.
//
// The package decides nothing about budgets: Pool.Limit and Pool.PreOpen call out to the node,
// which asks the limits sidecar. internal/node composes and wires it.
package public

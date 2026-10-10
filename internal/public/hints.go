package public

// Tool annotations (MCP ToolAnnotations): the four behavioural hints a host decides confirmations
// from. Every tool this node serves states all four as JSON booleans, each even where it equals
// the protocol's default (readOnlyHint false, destructiveHint true, idempotentHint false,
// openWorldHint true): a host that meets an absent hint assumes the default silently, and an app
// directory that requires the four refuses a tool missing any. go-sdk's DestructiveHint and
// OpenWorldHint are `*bool` with omitempty, so a nil pointer is a missing key on the wire; Hints
// is the one constructor, and it fills both.
//
// The hints are metadata for the caller's host and nothing else here: no permission or
// authorization decision reads them (SPEC.md §6.9).

import "github.com/modelcontextprotocol/go-sdk/mcp"

// Hints is the four hints of one tool, in MCP's order: read-only, destructive, idempotent, open
// world. Both pointer fields are set, so the four keys are always on the wire.
func Hints(ro, de, id, ow bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: ro, DestructiveHint: &de, IdempotentHint: id, OpenWorldHint: &ow}
}

// protocolHints is the hints of each HDTP tool (HDTP §6.2, §13.2): one table for both
// implementations, which BatonDeck records as batondeck/gateway/test/fixtures/go-protocol-tools.json
// and TestTheCloudsCopyOfTheProtocolHintsIsCurrent holds to this node's wire. openWorldHint is true only where
// the handler can leave this host: a calendar or status recipe calls the upstream tool it binds,
// and the sealed wrapper carries any inner call.
//
//   - redeem_invite, request_contact: add a row and spend a use or wake the owner; a repeat is
//     not neutral (a request that expired is made again), so neither is idempotent.
//   - contact_accepted, contact_rejected, update_contact, remove_contact: overwrite or delete the
//     caller's own row; the same call again changes nothing more.
//   - get_card: reads; its audit row and the chain-sent mark are the node's bookkeeping.
//   - send_message, send_media: append, idempotent on msg_id (messaging.Service.Record); a URL is
//     recorded and never fetched, so nothing leaves the host.
//   - get_status, check_availability: read, and a recipe may read them from an upstream.
//   - book_slot: creates upstream, idempotent on msg_id (providers.Calendar.BookSlot reserves it
//     first); cancel_booking removes upstream.
//   - sealed_call: carries any of the above, so it states the worst case of the set; a replay is
//     acknowledged from the record only when an idempotency store is configured.
var protocolHints = map[string]*mcp.ToolAnnotations{
	"redeem_invite":      Hints(false, false, false, false),
	"request_contact":    Hints(false, false, false, false),
	"contact_accepted":   Hints(false, true, true, false),
	"contact_rejected":   Hints(false, true, true, false),
	"get_card":           Hints(true, false, true, false),
	"update_contact":     Hints(false, true, true, false),
	"remove_contact":     Hints(false, true, true, false),
	"send_message":       Hints(false, false, true, false),
	"send_media":         Hints(false, false, true, false),
	"get_status":         Hints(true, false, true, true),
	"check_availability": Hints(true, false, true, true),
	"book_slot":          Hints(false, false, true, true),
	"cancel_booking":     Hints(false, true, true, true),
	SealedToolName:       Hints(false, true, false, true),
}

// hintsOf is the hints of one HDTP tool, a copy per tool definition. A name with no row is a
// programming error in this package — the set is closed (core.ReservedToolNames) — and is
// refused at construction rather than served without hints.
func hintsOf(name string) *mcp.ToolAnnotations {
	h, ok := protocolHints[name]
	if !ok {
		panic("public: " + name + " has no row in protocolHints; every HDTP tool states its four hints")
	}
	return Hints(h.ReadOnlyHint, *h.DestructiveHint, h.IdempotentHint, *h.OpenWorldHint)
}

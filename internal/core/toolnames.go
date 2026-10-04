package core

// ReservedToolNames is every name an integration's tool may not be exposed under (HDTP §8:
// integration tools sit beside the core ones): each built-in tool's (HDTP §6.2) and the envelope
// carrier's, `sealed_call`. The composed server's AddTool replaces a tool of the same name, while
// sealed dispatch serves the first entry that matches, the built-in, so an integration tool under a
// built-in's name answered one thing over a client certificate and another sealed. As the cloud
// reserves them (batondeck src/identity/rails.ts RESERVED_TOOL_NAMES).
//
// It is a list here, below the integrations that read it, and held to the served set — every
// public.BuiltinEntries name and public.SealedToolName, no more and no fewer — by
// internal/public TestTheReservedToolNamesAreTheBuiltInSet.
var ReservedToolNames = map[string]bool{
	"redeem_invite": true, "request_contact": true,
	"contact_accepted": true, "contact_rejected": true,
	"get_card": true, "update_contact": true, "remove_contact": true,
	"send_message": true, "send_media": true, "get_status": true,
	"check_availability": true, "book_slot": true, "cancel_booking": true,
	"sealed_call": true,
}

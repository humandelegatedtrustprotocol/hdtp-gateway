package core

// The name of each HDTP tool on the wire (HDTP §6.2) and of the envelope carrier: the one spelling
// every registration, hint row, reservation, audit action and outbound call uses.
const (
	ToolRedeemInvite      = "redeem_invite"
	ToolRequestContact    = "request_contact"
	ToolContactAccepted   = "contact_accepted"
	ToolContactRejected   = "contact_rejected"
	ToolGetCard           = "get_card"
	ToolUpdateContact     = "update_contact"
	ToolRemoveContact     = "remove_contact"
	ToolSendMessage       = "send_message"
	ToolSendMedia         = "send_media"
	ToolGetStatus         = "get_status"
	ToolCheckAvailability = "check_availability"
	ToolBookSlot          = "book_slot"
	ToolCancelBooking     = "cancel_booking"
	ToolSealedCall        = "sealed_call"
)

// ReservedToolNames is every name an integration's tool may not be exposed under (HDTP §8:
// integration tools sit beside the core ones): each built-in tool's (HDTP §6.2) and the envelope
// carrier's, `sealed_call`. The composed server's AddTool replaces a tool of the same name, while
// sealed dispatch serves the first entry that matches, the built-in, so an integration tool under a
// built-in's name answered one thing over a client certificate and another sealed. As the cloud
// reserves them (batondeck src/identity/rails.ts RESERVED_TOOL_NAMES).
//
// It is a set here, below the integrations that read it, and held to the served set — every
// public.BuiltinEntries name and ToolSealedCall, no more and no fewer — and to the wire names
// spelled out by hand, by internal/public TestTheReservedToolNamesAreTheBuiltInSet.
var ReservedToolNames = map[string]bool{
	ToolRedeemInvite: true, ToolRequestContact: true,
	ToolContactAccepted: true, ToolContactRejected: true,
	ToolGetCard: true, ToolUpdateContact: true, ToolRemoveContact: true,
	ToolSendMessage: true, ToolSendMedia: true, ToolGetStatus: true,
	ToolCheckAvailability: true, ToolBookSlot: true, ToolCancelBooking: true,
	ToolSealedCall: true,
}

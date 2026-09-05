package node

import "testing"

// Through an edge that strips client certificates a peer answers tools/list as
// to a stranger. That answer must be recognised as saying nothing, and replaced
// by what the contact actually granted — otherwise the composer offers nothing
// to a contact who enabled files and a calendar.
func TestGuestSurfaceIsRebuiltFromGrants(t *testing.T) {
	guest := []ContactTool{{Name: "redeem_invite"}, {Name: "request_contact"}, {Name: "sealed_call"}}
	if !looksGuest(guest) {
		t.Fatal("the guest surface was not recognised")
	}
	contact := []ContactTool{{Name: "get_card"}, {Name: "send_message"}, {Name: "sealed_call"}}
	if looksGuest(contact) {
		t.Fatal("a contact-tier answer was mistaken for the guest surface")
	}
	got := toolsFromGrants([]string{"message.text", "message.media", "calendar.book"})
	names := map[string]bool{}
	for _, g := range got {
		names[g.Name] = true
	}
	for _, want := range []string{"get_card", "send_message", "send_media", "book_slot", "cancel_booking"} {
		if !names[want] {
			t.Errorf("granted tool %s missing from %v", want, names)
		}
	}
	for _, no := range []string{"check_availability", "get_status"} {
		if names[no] {
			t.Errorf("%s offered without its permission", no)
		}
	}
}

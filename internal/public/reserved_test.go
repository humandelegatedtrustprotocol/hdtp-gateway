package public

import (
	"slices"
	"sort"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// core.ReservedToolNames is the list the integrations refuse an exposure under; this is the set
// that serves them. Two copies of one list, held to each other in both directions. Both are built
// from core's constants, so a misspelt constant would keep them equal; the wire names spelled out
// here by hand (HDTP §6.2 and the envelope carrier) are what the served set must be.
func TestTheReservedToolNamesAreTheBuiltInSet(t *testing.T) {
	served := map[string]bool{core.ToolSealedCall: true}
	for _, e := range BuiltinEntries(ToolDeps{}) {
		served[e.Tool.Name] = true
	}
	if len(served) < 14 {
		t.Fatalf("read %d served names; the built-in set is larger, so the reader is broken", len(served))
	}
	for name := range served {
		if !core.ReservedToolNames[name] {
			t.Errorf("%s is served and not reserved: an integration could take its name", name)
		}
	}
	for name := range core.ReservedToolNames {
		if !served[name] {
			t.Errorf("%s is reserved and not served: remove it from core.ReservedToolNames", name)
		}
	}

	wire := []string{
		"redeem_invite", "request_contact", "contact_accepted", "contact_rejected",
		"get_card", "update_contact", "remove_contact", "send_message", "send_media",
		"get_status", "check_availability", "book_slot", "cancel_booking", "sealed_call",
	}
	got := make([]string, 0, len(served))
	for name := range served {
		got = append(got, name)
	}
	sort.Strings(got)
	sort.Strings(wire)
	if !slices.Equal(got, wire) {
		t.Errorf("served %v; the wire names are %v", got, wire)
	}
}

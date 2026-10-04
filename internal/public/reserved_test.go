package public

import (
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// core.ReservedToolNames is the list the integrations refuse an exposure under; this is the set
// that serves them. Two copies of one list, held to each other in both directions.
func TestTheReservedToolNamesAreTheBuiltInSet(t *testing.T) {
	served := map[string]bool{SealedToolName: true}
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
}

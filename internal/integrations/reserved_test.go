package integrations

import (
	"context"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// HDTP §8: integration tools sit beside the core ones. An exposure under a built-in tool's name
// was published: the composed server's AddTool replaced the built-in, while sealed dispatch kept
// serving the built-in, so one name answered two ways. Every built-in name and `sealed_call` is
// refused for a passthrough or agent-answered entry, named or defaulted, and nothing is minted; the
// control, a name beside them, publishes.
func TestAnExposureNeverTakesABuiltInName(t *testing.T) {
	e, _, _, id := exposureEnv(t)
	ctx := context.Background()
	reserved := core.ReservedToolNames
	if !reserved["send_message"] || !reserved["sealed_call"] || !reserved["request_contact"] || len(reserved) < 14 {
		t.Fatalf("the reserved names are not the built-in set: %v", reserved)
	}
	for name := range reserved {
		for _, mode := range []string{ModePassthrough, ModeAgent} {
			if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: mode, ExposedName: name}}); err == nil || !strings.Contains(err.Error(), "built-in") {
				t.Errorf("%s as %s: %v", name, mode, err)
			}
		}
	}
	if latest, err := e.Store.LatestExposure(ctx, id); err == nil {
		t.Fatalf("a refused publish minted v%d", latest.Version)
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough, ExposedName: "cal_send_message"}}); err != nil {
		t.Fatalf("the control was refused: %v", err)
	}
}

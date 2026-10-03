package recipes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

type fixtureTool struct {
	Name       string   `json:"name"`
	Properties []string `json:"properties"`
}

// AC: each shipped recipe loads and maps against a schema fixture captured
// from its server's published tool defs — every bound tool exists and every
// arg the recipe builds is a field the server declares.
func TestRecipesMapOntoCapturedServerDefs(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("want the 4 verified recipes, got %d", len(all))
	}
	raw, err := os.ReadFile("testdata/upstream-defs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string][]fixtureTool
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	sample := map[string]any{
		"window_start": "2026-08-25T09:00:00Z", "window_end": "2026-08-25T17:00:00Z",
		"duration_minutes": 30, "start": "2026-08-25T10:00:00Z", "end": "2026-08-25T10:30:00Z",
		"subject": "Tea", "event_id": "evt-1",
		// A per-install recipe parameter, supplied as `integration.<slug>.calendar_url`
		// and reached as `$cfg.calendar_url`. Without one, a recipe for a server that
		// has no default collection cannot be written at all.
		"cfg.calendar_url": "http://radicale/owner/work/",
	}
	for name, rec := range all {
		tools := map[string]map[string]bool{}
		for _, ft := range fixtures[name] {
			props := map[string]bool{}
			for _, p := range ft.Properties {
				props[p] = true
			}
			tools[ft.Name] = props
		}
		if len(tools) == 0 {
			t.Fatalf("no fixture for recipe %s", name)
		}
		for capName, b := range rec.Capabilities {
			props, ok := tools[b.Tool]
			if !ok {
				t.Fatalf("%s: %s binds unknown tool %q", name, capName, b.Tool)
			}
			args, err := integrations.BuildArgs(b, sample)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, capName, err)
			}
			for field := range args {
				if !props[field] {
					t.Fatalf("%s/%s: arg %q not in %s's published schema", name, capName, field, b.Tool)
				}
			}
		}
	}
	// the official server's write-scope caveat ships in the recipe
	if !strings.Contains(strings.Join(all["google-official"].Caveats, " "), "UNVERIFIED") {
		t.Fatal("google-official recipe lost its write-scope caveat")
	}
	// workspace-mcp book/cancel carry the action constants
	if all["workspace-mcp"].Capabilities["book_slot"].Args["action"] != "create" ||
		all["workspace-mcp"].Capabilities["cancel_booking"].Args["action"] != "delete" {
		t.Fatal("manage_event action constants missing")
	}
}

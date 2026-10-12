package integrations

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// A publish the node refuses is ErrExposureRefused, each in its own words, and a publish to an
// integration with no catalog snapshot is ErrNoCatalog, with no store text: the doors code them
// bad_request and conflict. Both were plain errors (and the second carried "sql: no rows in result
// set"), which a door could only answer internal. The control, a valid publish, mints.
func TestAPublishIsRefusedByCode(t *testing.T) {
	e, _, _, id := exposureEnv(t)
	ctx := context.Background()
	for _, c := range []struct {
		entries []ExposureEntry
		text    string
	}{
		{[]ExposureEntry{{Tool: "nope", Mode: ModePassthrough}}, `integrations: tool "nope" is not in catalog v1`},
		{[]ExposureEntry{{Tool: "find_slots", Mode: "yolo"}}, `integrations: unknown serving mode "yolo"`},
		{[]ExposureEntry{{Tool: "find_slots", Mode: ModeAgent, Fallback: ModeAgent}}, `integrations: fallback "agent" must be passthrough or mapped`},
		{[]ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough, ExposedName: "get_card"}}, `integrations: "get_card" is a built-in tool's name and cannot be taken by an integration`},
	} {
		_, err := e.Publish(ctx, id, c.entries)
		if !errors.Is(err, ErrExposureRefused) || err.Error() != c.text {
			t.Errorf("%+v: %v, want ErrExposureRefused %q", c.entries, err, c.text)
		}
	}
	held, err := e.Store.GetIntegrationByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	in, err := e.Store.InsertIntegration(ctx, store.Integration{AccountID: held.AccountID, Slug: "bare", Transport: "streamable-http", Endpoint: "https://x/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Publish(ctx, in.ID, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}}); !errors.Is(err, ErrNoCatalog) || err.Error() != ErrNoCatalog.Error() {
		t.Errorf("no catalog: %v, want ErrNoCatalog alone", err)
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}}); err != nil {
		t.Fatalf("the control: %v", err)
	}
}

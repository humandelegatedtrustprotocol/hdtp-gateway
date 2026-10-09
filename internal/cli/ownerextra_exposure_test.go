package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/integrationchain"
)

// The owner MCP's set_exposure answers another account's integration exactly as it answers an id
// that is nobody's: the same error, wrapping store.ErrNotFound, nothing published, and no audit
// row of its own. It used to read the catalog first and compare accounts after, so a foreign id
// and a missing one answered different errors — an existence oracle the portal's 404 does not
// have — and the foreign one wrote a `permission_denied` row the missing one did not.
func TestSetExposureAnswersAForeignIntegrationAsAMissingOne(t *testing.T) {
	ctx := context.Background()
	st := migrated(t, t.TempDir())
	defer st.Close()
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "b", DisplayName: "B", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: b.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://upstream.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertCatalog(ctx, store.Catalog{
		IntegrationID: in.ID, Version: 1,
		Tools: `[{"name":"find_slots","description":"find","input_schema":{"type":"object"},"hash":"h1"}]`,
	}); err != nil {
		t.Fatal(err)
	}
	var rows []string
	audit := func(action, resource, outcome string) { rows = append(rows, action+" "+resource+" "+outcome) }
	chain := integrationchain.Build(st, nil, nil, "", audit, nil, nil, nil)
	extra := ownerExtra(nil, st, nil, chain, audit)

	// Authorized for A, naming B's integration, and naming an id that is nobody's.
	foreign := extra.SetExposure(ctx, a.ID, in.ID, []string{"find_slots"})
	missing := extra.SetExposure(ctx, a.ID, "no-such-integration", []string{"find_slots"})
	if foreign == nil || missing == nil {
		t.Fatalf("not refused: another account's integration %v, a missing id %v", foreign, missing)
	}
	if !errors.Is(foreign, store.ErrNotFound) || foreign.Error() != missing.Error() {
		t.Fatalf("told apart: another account's integration %q, a missing id %q", foreign, missing)
	}
	if _, err := st.LatestExposure(ctx, in.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B's exposure after A's attempt: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("a refused set_exposure wrote audit rows: %v", rows)
	}

	// The control: the integration's own account publishes.
	if err := extra.SetExposure(ctx, b.ID, in.ID, []string{"find_slots"}); err != nil {
		t.Fatalf("the integration's own account: %v", err)
	}
	if _, err := st.LatestExposure(ctx, in.ID); err != nil {
		t.Fatalf("nothing published for the integration's own account: %v", err)
	}
}

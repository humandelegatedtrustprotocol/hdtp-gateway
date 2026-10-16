package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
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

// set_exposure's refusal of a tool the integration does not offer is the node's own sentence,
// marked (refusal.BadRequest) so the owner MCP answers it bad_request with that sentence; it was a
// plain error, answered internal. The control, a tool it offers, publishes.
func TestSetExposureRefusesAnUnofferedToolWithAMarkedSentence(t *testing.T) {
	ctx := context.Background()
	st := migrated(t, t.TempDir())
	defer st.Close()
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://upstream.invalid",
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
	audit := func(string, string, string) {}
	extra := ownerExtra(nil, st, nil, integrationchain.Build(st, nil, nil, "", audit, nil, nil, nil), audit)

	err = extra.SetExposure(ctx, a.ID, in.ID, []string{"delete_everything"})
	want := `cal does not offer a tool called "delete_everything"`
	if code, got := refusal.Of(err); code != "bad_request" || got != want || err.Error() != want {
		t.Errorf("an unoffered tool: %v (%s %q), want bad_request %q", err, code, got, want)
	}
	if err := extra.SetExposure(ctx, a.ID, in.ID, []string{"find_slots"}); err != nil {
		t.Fatalf("the control: %v", err)
	}
}

// set_exposure on an integration with no catalog snapshot is integrations.ErrNoCatalog, which the
// owner MCP answers conflict: the store's not-found read as not_found, though the integration is
// there. The control, an integration with a snapshot, publishes.
func TestSetExposureWithNoCatalogIsErrNoCatalog(t *testing.T) {
	ctx := context.Background()
	st := migrated(t, t.TempDir())
	defer st.Close()
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	bare, err := st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "bare", Transport: "streamable-http", Endpoint: "https://upstream.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	audit := func(string, string, string) {}
	extra := ownerExtra(nil, st, nil, integrationchain.Build(st, nil, nil, "", audit, nil, nil, nil), audit)
	if err := extra.SetExposure(ctx, a.ID, bare.ID, []string{"find_slots"}); !errors.Is(err, integrations.ErrNoCatalog) {
		t.Errorf("no catalog: %v, want integrations.ErrNoCatalog", err)
	}
	if _, err := st.InsertCatalog(ctx, store.Catalog{IntegrationID: bare.ID, Version: 1,
		Tools: `[{"name":"find_slots","description":"find","input_schema":{"type":"object"},"hash":"h1"}]`}); err != nil {
		t.Fatal(err)
	}
	if err := extra.SetExposure(ctx, a.ID, bare.ID, []string{"find_slots"}); err != nil {
		t.Fatalf("the control: %v", err)
	}
}

// exposureReadFails is the store with LatestExposure failing.
type exposureReadFails struct{ store.Store }

func (exposureReadFails) LatestExposure(context.Context, string) (store.Exposure, error) {
	return store.Exposure{}, errors.New("sqlite: disk I/O error")
}

// list_integrations answers an exposure set that could not be read as an error (internal at the
// owner MCP), where it listed the integration with nothing exposed. The controls: an integration
// with nothing published lists with nothing exposed, and a published one lists its tool.
func TestListIntegrationsAnswersAnUnreadableExposureAsAnError(t *testing.T) {
	ctx := context.Background()
	st := migrated(t, t.TempDir())
	defer st.Close()
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://upstream.invalid",
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
	audit := func(string, string, string) {}
	extra := ownerExtra(nil, st, nil, integrationchain.Build(st, nil, nil, "", audit, nil, nil, nil), audit)
	list, err := extra.Integrations(ctx, a.ID)
	if err != nil || len(list) != 1 || len(list[0].Exposed) != 0 {
		t.Fatalf("nothing published: %+v %v, want the integration with nothing exposed", list, err)
	}
	if err := extra.SetExposure(ctx, a.ID, in.ID, []string{"find_slots"}); err != nil {
		t.Fatal(err)
	}
	if list, err := extra.Integrations(ctx, a.ID); err != nil || len(list) != 1 || len(list[0].Exposed) != 1 {
		t.Fatalf("published: %+v %v, want the tool exposed", list, err)
	}

	failing := exposureReadFails{st}
	extra = ownerExtra(nil, failing, nil, integrationchain.Build(failing, nil, nil, "", audit, nil, nil, nil), audit)
	list, err = extra.Integrations(ctx, a.ID)
	if err == nil {
		t.Fatalf("an unreadable exposure set: %+v, want an error", list)
	}
	if code, _ := refusal.Of(err); code != "internal" {
		t.Fatalf("an unreadable exposure set reads as %q, want internal", code)
	}
}

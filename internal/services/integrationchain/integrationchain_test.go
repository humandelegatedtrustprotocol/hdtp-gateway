package integrationchain

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// AC (P10-04a): the chain is wired, so the machinery P3 built actually runs.
//
// `serve` used to build integrations.Manager{Store: st} — one of thirteen fields
// — and the portal separately constructed its OWN Cataloger and Exposures with
// every hook nil. This asserts the connections exist rather than that any one of
// them fires, because the defect was structural: nothing was attached to
// anything.
func TestIntegrationChainIsWired(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	var audited []string
	changed := 0
	chain := Build(st, nil, nil, "",
		func(a, r, o string) { audited = append(audited, a+" "+o) },
		func(string) { changed++ }, nil, nil)

	if chain.Manager.Audit == nil {
		t.Error("Manager.Audit is nil — every audit call inside the manager is a no-op")
	}
	if chain.Manager.HTTPClient == nil || chain.Manager.HTTPClient.Timeout == 0 {
		t.Error("upstream calls have no timeout — one dead upstream pins a goroutine")
	}
	for name, hook := range map[string]func(string){
		"OnConnected":       chain.Manager.OnConnected,
		"OnHealthy":         chain.Manager.OnHealthy,
		"OnToolListChanged": chain.Manager.OnToolListChanged,
		"OnMinted":          chain.Cataloger.OnMinted,
		"OnChange":          chain.Exposures.OnChange,
	} {
		if hook == nil {
			t.Errorf("%s is nil — the surface it feeds never updates", name)
		}
	}
	if chain.Manager.OnAvailability == nil {
		t.Error("OnAvailability is nil — a withheld integration keeps its tools listed (§6.10)")
	}
	if chain.Cataloger.Manager != chain.Manager {
		t.Error("the cataloger snapshots a different manager than the node runs")
	}

	// A withhold must reach the serving surface and be audited (§6.10).
	chain.Manager.OnAvailability("i-1", true)
	if changed != 1 {
		t.Errorf("a withheld integration did not rebuild the served surface (%d)", changed)
	}
	var sawWithheld bool
	for _, a := range audited {
		if a == "integration_availability withheld" {
			sawWithheld = true
		}
	}
	if !sawWithheld {
		t.Errorf("the withhold was not audited: %v", audited)
	}

	// The stale guard is reachable from a minted snapshot and is a no-op when
	// nothing is exposed — it must not error on a bare integration.
	acct, err := st.CreateAccount(context.Background(), store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256",
	})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(context.Background(), store.Integration{
		AccountID: acct.ID, Slug: "cal", Transport: "streamable-http",
		Endpoint: "https://x.invalid", AuthKind: "none", Status: "disabled",
	})
	if err != nil {
		t.Fatal(err)
	}
	chain.Cataloger.OnMinted(in.ID)
}

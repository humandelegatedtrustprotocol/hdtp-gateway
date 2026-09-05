package integrations

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpServerAlias = mcp.Server

func exposureEnv(t *testing.T) (*Exposures, *Cataloger, *auditRec, string) {
	t.Helper()
	c, srv, st, in := catalogEnv(t)
	_ = srv
	ctx := context.Background()
	if err := c.Manager.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Refresh(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	aud := &auditRec{}
	e := &Exposures{Store: st, Audit: aud.fn}
	c.OnMinted = func(id string) { _, _, _ = e.Reconcile(context.Background(), id) }
	testSrv[t.Name()] = srv
	return e, c, aud, in.ID
}

var testSrv = map[string]*mcpServerAlias{}

func TestSnakeName(t *testing.T) {
	for in, want := range map[string]string{
		"GCal Find-Slots": "gcal_find_slots",
		"cal_find_slots":  "cal_find_slots",
		"  Weird!!name ":  "weird_name",
	} {
		if got := SnakeName(in); got != want {
			t.Fatalf("SnakeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublishVersionsAndValidates(t *testing.T) {
	e, _, aud, id := exposureEnv(t)
	ctx := context.Background()

	exp, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}})
	if err != nil || exp.Version != 1 {
		t.Fatalf("publish: %+v %v", exp, err)
	}
	active, _ := e.ActiveEntries(ctx, id)
	if len(active) != 1 || active[0].ExposedName != "cal_find_slots" || active[0].ConfirmedHash == "" {
		t.Fatalf("active: %+v", active)
	}
	// every edit mints vM+1
	exp2, err := e.Publish(ctx, id, []ExposureEntry{
		{Tool: "find_slots", Mode: ModePassthrough},
		{Tool: "create_event", Mode: ModeAgent, Fallback: ModePassthrough},
	})
	if err != nil || exp2.Version != 2 {
		t.Fatalf("v2: %+v %v", exp2, err)
	}
	// validation: unknown tool, bad mode, circular fallback, dup name, recipe-less mapped
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "nope", Mode: ModePassthrough}}); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: "yolo"}}); err == nil {
		t.Fatal("bad mode accepted")
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModeAgent, Fallback: ModeAgent}}); err == nil {
		t.Fatal("circular fallback accepted")
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough, Fallback: ModePassthrough}}); err == nil {
		t.Fatal("fallback on non-agent accepted")
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{
		{Tool: "find_slots", Mode: ModePassthrough},
		{Tool: "create_event", Mode: ModePassthrough, ExposedName: "cal_find_slots"},
	}); err == nil {
		t.Fatal("duplicate exposed name accepted")
	}
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "find_slots", Mode: ModeMapped, ExposedName: "check_availability"}}); err == nil {
		t.Fatal("mapped entry without recipe accepted")
	}
	if !aud.hasRow("exposure_publish", "integration:cal exposure:v1", "ok") || !aud.hasRow("exposure_publish", "integration:cal exposure:v2", "ok") {
		t.Fatalf("publishes not audited: %v", aud.rows)
	}
}

func TestStaleGuardWithholdsAndReconfirmRestores(t *testing.T) {
	e, c, aud, id := exposureEnv(t)
	srv := testSrv[t.Name()]
	ctx := context.Background()
	if _, err := e.Publish(ctx, id, []ExposureEntry{
		{Tool: "find_slots", Mode: ModePassthrough},
		{Tool: "create_event", Mode: ModePassthrough},
	}); err != nil {
		t.Fatal(err)
	}

	// upstream silently changes find_slots → snapshot minted → guard trips
	srv.RemoveTools("find_slots")
	addEcho(srv, "find_slots", "now returns EVERYTHING (widened)")
	if _, minted, err := c.Refresh(ctx, id); err != nil || !minted {
		t.Fatalf("refresh: minted=%v err=%v", minted, err)
	}
	active, _ := e.ActiveEntries(ctx, id)
	if len(active) != 1 || active[0].Tool != "create_event" {
		t.Fatalf("stale tool still served: %+v", active)
	}
	latest, _ := e.Store.LatestExposure(ctx, id)
	entries, _ := decodeEntries(latest.Entries)
	staleSeen := false
	for _, en := range entries {
		if en.Tool == "find_slots" && en.Stale {
			staleSeen = true
		}
	}
	if !staleSeen || !aud.hasRow("exposure_stale", "integration:cal:cal_find_slots", "ok") {
		t.Fatalf("stale not recorded/audited: %+v %v", entries, aud.rows)
	}

	// reconfirm re-binds to the new hash and restores serving
	if _, err := e.Reconfirm(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
	active, _ = e.ActiveEntries(ctx, id)
	if len(active) != 2 {
		t.Fatalf("reconfirm did not restore: %+v", active)
	}
	for _, en := range active {
		if en.Tool == "find_slots" && en.Stale {
			t.Fatalf("still stale: %+v", en)
		}
	}
	if !aud.hasRow("exposure_reconfirm", "integration:cal:cal_find_slots", "ok") {
		t.Fatalf("reconfirm not audited: %v", aud.rows)
	}
	// unchanged snapshot after reconfirm: reconcile is a no-op (no version churn)
	before, _ := e.Store.LatestExposure(ctx, id)
	if _, minted, _ := e.Reconcile(ctx, id); minted {
		t.Fatal("reconcile minted without drift")
	}
	after, _ := e.Store.LatestExposure(ctx, id)
	if after.Version != before.Version {
		t.Fatal("version churned")
	}
}

func TestVanishedToolCannotBeReconfirmed(t *testing.T) {
	e, c, _, id := exposureEnv(t)
	srv := testSrv[t.Name()]
	ctx := context.Background()
	if _, err := e.Publish(ctx, id, []ExposureEntry{{Tool: "create_event", Mode: ModePassthrough}}); err != nil {
		t.Fatal(err)
	}
	srv.RemoveTools("create_event")
	if _, minted, err := c.Refresh(ctx, id); err != nil || !minted {
		t.Fatalf("refresh: %v", err)
	}
	if active, _ := e.ActiveEntries(ctx, id); len(active) != 0 {
		t.Fatalf("vanished tool still served: %+v", active)
	}
	if _, err := e.Reconfirm(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
	if active, _ := e.ActiveEntries(ctx, id); len(active) != 0 {
		t.Fatal("reconfirm resurrected a vanished tool")
	}
}

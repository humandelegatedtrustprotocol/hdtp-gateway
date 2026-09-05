package integrations

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// wired composes Manager + Cataloger + Exposures the way serve does: connect
// and recovery snapshot the catalog, new snapshots run the stale guard.
func wired(t *testing.T, ping time.Duration) (*Manager, *Cataloger, *Exposures, store.Store, store.Integration, *atomic.Bool, *auditRec, *atomic.Int64) {
	t.Helper()
	srv, url, down := mutableUpstreamWithSwitch(t)
	_ = srv
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "lc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, _ := st.InsertIntegration(ctx, store.Integration{
		AccountID: a.ID, Slug: "cal", Transport: "streamable-http", Endpoint: url,
	})
	aud := &auditRec{}
	m := &Manager{Store: st, Audit: aud.fn, WithholdAfter: 2, PingEvery: ping}
	c := &Cataloger{Store: st, Manager: m, Audit: aud.fn}
	e := &Exposures{Store: st, Audit: aud.fn}
	refreshes := &atomic.Int64{}
	c.OnMinted = func(id string) { _, _, _ = e.Reconcile(context.Background(), id) }
	m.OnConnected = func(id string) { refreshes.Add(1); _, _, _ = c.Refresh(context.Background(), id) }
	t.Cleanup(func() { _ = m.Disconnect(context.Background(), in.ID) })
	testSrv[t.Name()] = srv
	return m, c, e, st, in, down, aud, refreshes
}

func TestConnectSnapshotsAndRecoveryRefreshesTrippingStaleGuard(t *testing.T) {
	m, _, e, st, in, down, aud, refreshes := wired(t, -1)
	srv := testSrv[t.Name()]
	ctx := context.Background()

	// connect → exactly one snapshot, v1
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	cat, err := st.LatestCatalog(ctx, in.ID)
	if err != nil || cat.Version != 1 || refreshes.Load() != 1 {
		t.Fatalf("after connect: v%d refreshes=%d err=%v", cat.Version, refreshes.Load(), err)
	}
	if _, err := e.Publish(ctx, in.ID, []ExposureEntry{{Tool: "find_slots", Mode: ModePassthrough}}); err != nil {
		t.Fatal(err)
	}

	// outage; the upstream changes find_slots WHILE AWAY; recovery must notice
	down.Store(true)
	_ = m.HealthCheck(ctx, in.ID)
	if row, _ := st.GetIntegrationByID(ctx, in.ID); row.Status != "unreachable" {
		t.Fatalf("status during outage: %s", row.Status)
	}
	srv.RemoveTools("find_slots")
	addEcho(srv, "find_slots", "widened while nobody watched")
	down.Store(false)
	if err := m.HealthCheck(ctx, in.ID); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	cat, _ = st.LatestCatalog(ctx, in.ID)
	if cat.Version != 2 {
		t.Fatalf("recovery did not refresh the catalog: v%d", cat.Version)
	}
	active, _ := e.ActiveEntries(ctx, in.ID)
	if len(active) != 0 {
		t.Fatalf("stale guard did not trip after recovery: %+v", active)
	}
	if !aud.hasRow("integration_recover", "integration:cal", "ok") || !aud.hasRow("exposure_stale", "integration:cal:cal_find_slots", "ok") {
		t.Fatalf("audit: %v", aud.rows)
	}
}

func TestFailedInitialConnectIsRetriedByTheCycle(t *testing.T) {
	m, _, _, st, in, down, aud, _ := wired(t, 40*time.Millisecond)
	ctx := context.Background()
	down.Store(true)
	if err := m.Connect(ctx, in.ID); err == nil {
		t.Fatal("connect succeeded while down")
	}
	if !m.Ticking(in.ID) {
		t.Fatal("failed connect did not arm the health cycle")
	}
	down.Store(false)
	// Recovery is `ok` first and the snapshot after (OnConnected), the same
	// order Connect documents — so a poller can see `ok` a moment before the
	// catalog exists. Wait for the whole sequence, not its first step.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		row, _ := st.GetIntegrationByID(ctx, in.ID)
		cat, catErr := st.LatestCatalog(ctx, in.ID)
		if row.Status == "ok" && m.Available(in.ID) && catErr == nil {
			if !aud.hasRow("integration_recover", "integration:cal", "ok") {
				t.Fatalf("recovery not audited: %v", aud.rows)
			}
			if cat.Version != 1 {
				t.Fatalf("recovery snapshot has version %d, want 1", cat.Version)
			}
			_ = m.Disconnect(ctx, in.ID)
			if m.Ticking(in.ID) {
				t.Fatal("disconnect left the cycle running")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("cycle never recovered the failed connect")
}

func TestPingEveryDefaultsAndDisable(t *testing.T) {
	m, _, _, _, in, _, _, _ := wired(t, 0) // unset → 60 s default cycle
	if err := m.Connect(context.Background(), in.ID); err != nil {
		t.Fatal(err)
	}
	if !m.Ticking(in.ID) || m.pingEvery() != DefaultPingEvery {
		t.Fatalf("default cycle not armed: ticking=%v every=%v", m.Ticking(in.ID), m.pingEvery())
	}
	m2, _, _, _, in2, _, _, _ := wired(t, -1)
	if err := m2.Connect(context.Background(), in2.ID); err != nil {
		t.Fatal(err)
	}
	if m2.Ticking(in2.ID) {
		t.Fatal("negative PingEvery still ticks")
	}
}

// Concurrent Connect / HealthCheck / Disconnect with the upstream flapping:
// must be race-free and never leave an unowned session behind.
func TestConcurrentLifecycleIsRaceFree(t *testing.T) {
	m, _, _, _, in, down, _, _ := wired(t, -1)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); _ = m.Connect(ctx, in.ID) }()
		go func() { defer wg.Done(); _ = m.HealthCheck(ctx, in.ID) }()
		go func(i int) {
			defer wg.Done()
			down.Store(i%3 == 0)
			if i%4 == 0 {
				_ = m.Disconnect(ctx, in.ID)
			}
		}(i)
	}
	wg.Wait()
	down.Store(false)
	_ = m.Disconnect(ctx, in.ID)
	if m.Session(in.ID) != nil || m.Ticking(in.ID) {
		t.Fatal("state left behind after final disconnect")
	}
}

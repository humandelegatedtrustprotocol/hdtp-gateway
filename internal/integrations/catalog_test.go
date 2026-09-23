package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

type echoArgs struct {
	Text string `json:"text"`
}

func addEcho(srv *mcp.Server, name, desc string) {
	mcp.AddTool(srv, &mcp.Tool{Name: name, Description: desc},
		func(ctx context.Context, req *mcp.CallToolRequest, a echoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: a.Text}}}, nil, nil
		})
}

// mutableUpstream is a fake MCP server whose tool set the test can edit live
// and whose reachability can be cut (down => 503 on every request).
func mutableUpstream(t *testing.T) (*mcp.Server, string) {
	t.Helper()
	srv, url, _ := mutableUpstreamWithSwitch(t)
	return srv, url
}

func mutableUpstreamWithSwitch(t *testing.T) (*mcp.Server, string, *atomic.Bool) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake-cal", Version: "0"}, nil)
	addEcho(srv, "find_slots", "Find free calendar slots")
	addEcho(srv, "create_event", "Create a calendar event")
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	down := &atomic.Bool{}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(hs.Close)
	return srv, hs.URL, down
}

func catalogEnv(t *testing.T) (*Cataloger, *mcp.Server, store.Store, store.Integration) {
	t.Helper()
	srv, url := mutableUpstream(t)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
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
	m := &Manager{Store: st, Audit: aud.fn, PingEvery: -1}
	t.Cleanup(func() { _ = m.Disconnect(context.Background(), in.ID) })
	c := &Cataloger{Store: st, Manager: m, Audit: aud.fn}
	return c, srv, st, in
}

func TestSnapshotMintsOnlyOnChange(t *testing.T) {
	c, srv, st, in := catalogEnv(t)
	ctx := context.Background()
	if err := c.Manager.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	cat1, minted, err := c.Refresh(ctx, in.ID)
	if err != nil || !minted || cat1.Version != 1 {
		t.Fatalf("first refresh: v%d minted=%v err=%v", cat1.Version, minted, err)
	}
	// unchanged upstream: same hashes, no new version
	cat2, minted, err := c.Refresh(ctx, in.ID)
	if err != nil || minted || cat2.Version != 1 || cat2.Tools != cat1.Tools {
		t.Fatalf("unchanged refresh minted: v%d minted=%v err=%v", cat2.Version, minted, err)
	}
	// changed description => new version
	srv.RemoveTools("find_slots")
	addEcho(srv, "find_slots", "Find free calendar slots (rev 2)")
	cat3, minted, err := c.Refresh(ctx, in.ID)
	if err != nil || !minted || cat3.Version != 2 {
		t.Fatalf("changed refresh: v%d minted=%v err=%v", cat3.Version, minted, err)
	}
	// added + removed => another version
	srv.RemoveTools("create_event")
	addEcho(srv, "delete_event", "Delete an event")
	cat4, minted, _ := c.Refresh(ctx, in.ID)
	if !minted || cat4.Version != 3 {
		t.Fatalf("v%d minted=%v", cat4.Version, minted)
	}
	// store round-trip: latest is v3, v1 still immutable
	latest, _ := st.LatestCatalog(ctx, in.ID)
	if latest.Version != 3 {
		t.Fatalf("latest: v%d", latest.Version)
	}
	v1, err := st.GetCatalog(ctx, in.ID, 1)
	if err != nil || v1.Tools != cat1.Tools {
		t.Fatalf("v1 changed: %v", err)
	}
}

func TestToolListChangedTriggersSnapshot(t *testing.T) {
	c, srv, st, in := catalogEnv(t)
	ctx := context.Background()
	var refreshes atomic.Int64
	c.Manager.OnToolListChanged = func(id string) {
		if id == in.ID {
			refreshes.Add(1)
			_, _, _ = c.Refresh(context.Background(), id)
		}
	}
	if err := c.Manager.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Refresh(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	// live tool-set change → server pushes list_changed → snapshot v2 appears
	addEcho(srv, "check_availability", "Coarse availability")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if latest, err := st.LatestCatalog(ctx, in.ID); err == nil && latest.Version >= 2 {
			if refreshes.Load() == 0 {
				t.Fatal("version bumped without the handler firing")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no snapshot after list_changed (refreshes=%d)", refreshes.Load())
}

package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// passthroughEnv: a LIVE upstream whose schema and behavior differ from the
// snapshot, so snapshot-vs-live is provable. The live tool accepts anything
// (low-level registration, no validation) and counts calls.
var testDelay = map[string]*atomic.Int64{}

func passthroughEnv(t *testing.T) (*Passthrough, ToolDef, *atomic.Int64, *atomic.Pointer[string]) {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "up", Version: "0"}, nil)
	calls := &atomic.Int64{}
	delay := &atomic.Int64{}
	testDelay[t.Name()] = delay
	reply := &atomic.Pointer[string]{}
	ok := "ok"
	reply.Store(&ok)
	// LIVE schema requires "z" — deliberately different from the snapshot below.
	srv.AddTool(&mcp.Tool{
		Name:        "do_thing",
		InputSchema: json.RawMessage(`{"type":"object","required":["z"]}`),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		if d := delay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: *reply.Load()}}}, nil
	})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	hs := httptest.NewServer(h)
	t.Cleanup(hs.Close)

	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pt.db"))
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
		AccountID: a.ID, Slug: "up", Transport: "streamable-http", Endpoint: hs.URL,
	})
	m := &Manager{Store: st, PingEvery: -1}
	t.Cleanup(func() { _ = m.Disconnect(context.Background(), in.ID) })
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	// SNAPSHOT schema requires string "a" — NOT what the live server says now.
	def := ToolDef{
		Name:        "do_thing",
		InputSchema: json.RawMessage(`{"type":"object","required":["a"],"properties":{"a":{"type":"string"}},"additionalProperties":false}`),
		Hash:        "h1",
	}
	p := &Passthrough{Manager: m, Timeout: 2 * time.Second, MaxResultBytes: 1024}
	testIntegration[t.Name()] = in.ID
	return p, def, calls, reply
}

var testIntegration = map[string]string{}

func call(t *testing.T, h mcp.ToolHandler, args string) *mcp.CallToolResult {
	t.Helper()
	res, err := h(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "x", Arguments: json.RawMessage(args)},
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestSnapshotSchemaGovernsNotLive(t *testing.T) {
	p, def, calls, _ := passthroughEnv(t)
	h, err := p.Handler("acct-test", testIntegration[t.Name()], def)
	if err != nil {
		t.Fatal(err)
	}
	// invalid per snapshot (missing "a") though VALID per live schema ("z" present):
	// rejected bad_request, upstream untouched
	res := call(t, h, `{"z":1}`)
	if !res.IsError || !strings.Contains(text(res), "bad_request") || calls.Load() != 0 {
		t.Fatalf("live schema leaked in: %v calls=%d", text(res), calls.Load())
	}
	// wrong type per snapshot
	if res := call(t, h, `{"a":42}`); !res.IsError || calls.Load() != 0 {
		t.Fatalf("type violation forwarded: calls=%d", calls.Load())
	}
	// valid per snapshot (INVALID per live's requires-z): forwarded and relayed —
	// proof the snapshot, not the live schema, governs
	res = call(t, h, `{"a":"hi"}`)
	if res.IsError || text(res) != "ok" || calls.Load() != 1 {
		t.Fatalf("snapshot-valid call failed: err=%v %q calls=%d", res.IsError, text(res), calls.Load())
	}
}

func TestOversizedResponseTruncatedWithError(t *testing.T) {
	p, def, _, reply := passthroughEnv(t)
	h, _ := p.Handler("acct-test", testIntegration[t.Name()], def)
	big := strings.Repeat("x", 5000) // cap is 1024
	reply.Store(&big)
	res := call(t, h, `{"a":"hi"}`)
	if !res.IsError || !strings.Contains(text(res), "too_large") {
		t.Fatalf("oversize not flagged: %q", text(res))
	}
	if len(res.Content) < 2 {
		t.Fatal("no truncated preview")
	}
	if tc := res.Content[1].(*mcp.TextContent); len(tc.Text) != 1024 || !strings.HasPrefix(big, tc.Text) {
		t.Fatalf("preview wrong: %d bytes", len(tc.Text))
	}
}

func TestTimeoutSurfacesUnavailable(t *testing.T) {
	p, def, _, _ := passthroughEnv(t)
	p.Timeout = 150 * time.Millisecond
	testDelay[t.Name()].Store(int64(time.Second))
	h, _ := p.Handler("acct-test", testIntegration[t.Name()], def)
	res := call(t, h, `{"a":"hi"}`)
	if !res.IsError || !strings.Contains(text(res), "unavailable") {
		t.Fatalf("timeout not unavailable: %q", text(res))
	}
}

func TestOutageSurfacesUnavailableWithoutForward(t *testing.T) {
	p, def, calls, _ := passthroughEnv(t)
	id := testIntegration[t.Name()]
	h, _ := p.Handler("acct-test", id, def)
	_ = p.Manager.Disconnect(context.Background(), id)
	res := call(t, h, `{"a":"hi"}`)
	if !res.IsError || !strings.Contains(text(res), "unavailable") || calls.Load() != 0 {
		t.Fatalf("outage call: %q calls=%d", text(res), calls.Load())
	}
}

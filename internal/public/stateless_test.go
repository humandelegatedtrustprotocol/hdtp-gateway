package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// StatelessMCP composes a request's server once, although the go-sdk asks for it twice per POST,
// so whatever compose does besides composing — resolving the caller, recording an owner agent as
// present — happens once per request; and GET and DELETE are answered 405 before anything is
// composed, so a flood of them composes nothing.
func TestStatelessMCPComposesOncePerRequestAndNeverForAGet(t *testing.T) {
	var composed atomic.Int64
	h := StatelessMCP(func(*http.Request) *mcp.Server {
		composed.Add(1)
		return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, &mcp.ServerOptions{Capabilities: ToolsOnly()})
	}, mcp.StreamableHTTPOptions{})

	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/mcp", nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Fatalf("%s: %d Allow %q, want 405 Allow POST", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if n := composed.Load(); n != 0 {
		t.Fatalf("a GET, DELETE or PUT composed %d servers", n)
	}

	const requests = 3
	for i := 0; i < requests; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Mcp-Session-Id") != "" {
			t.Fatalf("tools/list: %d, session %q", rec.Code, rec.Header().Get("Mcp-Session-Id"))
		}
	}
	if n := composed.Load(); n != requests {
		t.Fatalf("%d requests composed %d servers, want one each", requests, n)
	}
}

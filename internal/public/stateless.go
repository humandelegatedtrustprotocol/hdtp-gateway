package public

import (
	"context"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// StatelessMCP is how the node serves MCP, on the public surface and on the owner MCP alike
// (SPEC §5.5, §8.5): stateless Streamable HTTP. Every POST is the whole of its exchange. No
// session is issued or read — a presented `Mcp-Session-Id` is ignored — so any node process can
// answer any request, and a client of the 2026-07-28 revision (`server/discover`, the per-request
// `_meta`) is served as well as a client of the handshake revisions, which the SDK serves each
// request with a temporary session of default parameters.
//
// compose builds the server for the caller the request carries. The go-sdk asks for it twice per
// POST (once to check the version header, once to serve), so it is composed once per request here
// and the second ask gets the same server: whatever compose does besides composing, it does once.
// GET and DELETE, which only a session could give a meaning to, are answered 405 with `Allow: POST`
// before anything is composed.
//
// The handler's context ends with the request's for a 2026-07-28 client
// (PropagateRequestCancellation): a caller that hangs up mid-`wait_for_updates` stops holding the
// wait.
func StatelessMCP(compose func(*http.Request) *mcp.Server, opts mcp.StreamableHTTPOptions) http.Handler {
	opts.Stateless = true
	opts.PropagateRequestCancellation = true
	sdk := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		c := r.Context().Value(composedKey{}).(*composed)
		c.once.Do(func() { c.srv = compose(r) })
		return c.srv
	}, &opts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		sdk.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), composedKey{}, &composed{})))
	})
}

type composedKey struct{}

// composed is one request's server, composed at most once.
type composed struct {
	once sync.Once
	srv  *mcp.Server
}

// ToolsOnly is the capability set a server on the public surface declares: tools, with no
// `listChanged`. Nothing carries a list-change notification to a stateless client, and a client
// told there would be one opens `subscriptions/listen` for it; a client re-lists instead.
func ToolsOnly() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}
}

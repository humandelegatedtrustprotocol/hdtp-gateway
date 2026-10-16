package outbound

// A peer whose edge refuses the MCP handshake itself — `server/discover` and `initialize` — with a
// JSON-RPC error carrying an HDTP §12 code in `data`, as BatonDeck's edge does once a source's
// budget is spent before the handshake (gateway/src/identity/peer-metadata.ts, peerRefusal), is
// read as that peer refusing the call (#135): a tool error carrying the code and `retry_after` and
// nothing else it sent, on a plaintext call and on a sealed one alike, and a sealed exchange does
// not record that the peer has seen our chain, since the envelope never reached it. The SDK
// returned the error text `calling "initialize": rate_limited`, and the wait was lost.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// refusingEdge answers every JSON-RPC request with the error the edge answers a spent budget with,
// data as given; methods records what was asked.
func refusingEdge(t *testing.T, data string, methods *[]string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(b, &req)
		*methods = append(*methods, req.Method)
		id := "null"
		if len(req.ID) > 0 {
			id = string(req.ID)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+id+`,"error":{"code":-32000,"message":"rate_limited","data":`+data+`}}`)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestARefusedHandshakeIsThePeersRefusalWithItsWait(t *testing.T) {
	ctx := context.Background()
	const want = `{"code":"rate_limited","retry_after":7}`
	var methods []string
	ts := refusingEdge(t, `{"code":"rate_limited","retry_after":7,"message":"words of the edge"}`, &methods)
	peerID := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	caller := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp").client()
	sawChain := false
	caller.OnChainSent = func(Peer) { sawChain = true }

	plain := peerID.peerOf()
	plain.Endpoint, plain.Seal = ts.URL, "none"
	res, err := caller.CallTool(ctx, plain, "get_card", map[string]any{}, CallOptions{Plaintext: true})
	if err != nil || !res.IsError || len(res.Content) != 1 || res.Content[0].(*mcp.TextContent).Text != want {
		t.Fatalf("plaintext: %v %+v, want the tool error %s (asked %v)", err, res, want, methods)
	}

	sealed := peerID.peerOf()
	sealed.Endpoint, sealed.Seal = ts.URL, "required"
	res, err = caller.SealedCall(ctx, sealed, "send_message", map[string]any{"text": "hi"}, "m-1")
	if err != nil || !res.IsError || res.Content[0].(*mcp.TextContent).Text != want {
		t.Fatalf("sealed: %v %+v, want the tool error %s", err, res, want)
	}
	if sawChain {
		t.Error("a sealed call whose handshake was refused recorded that the peer has seen our chain")
	}

	// The control: a JSON-RPC error that names no §12 code is a failure of the call, not an answer.
	ts = refusingEdge(t, `{"why":"something else"}`, &methods)
	plain.Endpoint = ts.URL
	if res, err := caller.CallTool(ctx, plain, "get_card", map[string]any{}, CallOptions{Plaintext: true}); err == nil {
		t.Fatalf("a refusal with no code was read as the peer's answer: %+v", res)
	}
}

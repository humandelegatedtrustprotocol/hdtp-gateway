package outbound

// A carrier cannot read a sealed call. It can still ANSWER one — and until this
// change the caller believed whatever it said.
//
// PACT §13.2 draws the line: "once a request envelope has been successfully
// opened, an error result MUST be sealed back like any other result — a
// plaintext error is only for an envelope that could not be opened at all."
// So every code that is decided after the open is, in plaintext, a forgery by
// construction. `permission_denied` is the sharp one: the owner is shown a
// contact refusing them, and the contact never said a word.
//
// In edge mode the carrier is there by design — Cloudflare terminates the TLS —
// so this is not a hypothetical position for an attacker to reach.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// forgingPeer answers every sealed_call with one plaintext refusal.
func forgingPeer(t *testing.T, code string) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "carrier", Version: "1"}, nil)
	body := `{"code":"` + code + `"}`
	if code == "" {
		body = `not json at all`
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "sealed_call", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: body}}}, nil, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

func TestAPlaintextRefusalPastTheOpenIsNotThePeersAnswer(t *testing.T) {
	ctx := context.Background()
	peerID := newIdentity20(t, "Bharat", "https://agent.bharat.example/mcp")
	caller := newIdentity20(t, "Alina", "https://agent.alina.example/mcp").client()
	leafSPKI := mustSPKIOfLeaf(peerID.leaf)

	// Codes that can only be reached after the envelope opened. None of them
	// may be attributed to the peer when they arrive in the clear.
	for _, code := range []string{"permission_denied", "unknown_contact", "blocked_or_unknown", "invite_invalid", "pending_approval", ""} {
		ts := forgingPeer(t, code)
		p := peerID.peerOf()
		p.Endpoint, p.ChainSeen = ts.URL, true
		_, refusal, err := caller.sealedExchange20(ctx, p, leafSPKI, "tools/call", map[string]any{"name": "send_message"}, "m-1")
		if refusal != nil {
			t.Fatalf("%q: a forged plaintext refusal was reported as the peer's answer", code)
		}
		if err == nil || !strings.Contains(err.Error(), "§13.2") {
			t.Fatalf("%q: want an unattributable-answer error, got %v", code, err)
		}
	}

	// And the codes a peer CAN legitimately reach before opening still come
	// back as the peer's answer, so the rule refuses forgeries rather than
	// breaking the exchange.
	for _, code := range []string{"seal_required", "identity_required", "rate_limited", "unavailable", "bad_request", "too_large", "envelope_invalid"} {
		ts := forgingPeer(t, code)
		p := peerID.peerOf()
		p.Endpoint, p.ChainSeen = ts.URL, true
		_, refusal, err := caller.sealedExchange20(ctx, p, leafSPKI, "tools/call", map[string]any{"name": "send_message"}, "m-2")
		if err != nil {
			t.Fatalf("%q: %v", code, err)
		}
		if got, _ := refusalCode(refusal); got != code {
			t.Fatalf("%q: a pre-open refusal must be reported, got %q", code, got)
		}
	}
}

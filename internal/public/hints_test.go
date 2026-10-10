package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
)

// wantProtocolHints is what each HDTP tool says of itself, as read-only, destructive, idempotent,
// open-world: the plan of 2026-10-10 and BatonDeck's fixture, written here a second time so the
// table in hints.go is held to it.
var wantProtocolHints = map[string][4]bool{
	"redeem_invite":      {false, false, false, false},
	"request_contact":    {false, false, false, false},
	"contact_accepted":   {false, true, true, false},
	"contact_rejected":   {false, true, true, false},
	"get_card":           {true, false, true, false},
	"update_contact":     {false, true, true, false},
	"remove_contact":     {false, true, true, false},
	"send_message":       {false, false, true, false},
	"send_media":         {false, false, true, false},
	"get_status":         {true, false, true, true},
	"check_availability": {true, false, true, true},
	"book_slot":          {false, false, true, true},
	"cancel_booking":     {false, true, true, true},
	"sealed_call":        {false, true, false, true},
}

// hintKeys are the four, in the order wantProtocolHints gives them.
var hintKeys = [4]string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}

// hintsOnTheWire reads one tool as `tools/list` sent it and returns its name and its four hints.
// It fails for a tool whose `annotations` is not exactly the four keys, each a JSON boolean: a
// missing key is what go-sdk's omitempty pointers produce when one is left nil, and a host that
// meets it assumes the default.
func hintsOnTheWire(t *testing.T, tool json.RawMessage) (string, [4]bool) {
	t.Helper()
	var tl struct {
		Name        string                     `json:"name"`
		Annotations map[string]json.RawMessage `json:"annotations"`
	}
	if err := json.Unmarshal(tool, &tl); err != nil {
		t.Fatalf("a tool on the wire does not decode: %v\n%s", err, tool)
	}
	if len(tl.Annotations) != 4 {
		t.Fatalf("%s: annotations carry %d keys, want exactly the four hints\n%s", tl.Name, len(tl.Annotations), tool)
	}
	var got [4]bool
	for i, k := range hintKeys {
		switch string(tl.Annotations[k]) {
		case "true":
			got[i] = true
		case "false":
		default:
			t.Fatalf("%s: %s is %q on the wire, want true or false", tl.Name, k, tl.Annotations[k])
		}
	}
	return tl.Name, got
}

// wireToolsList is `tools/list` as the node's transport sends it: the go-sdk Streamable HTTP
// handler in the stateless, JSON-response mode StatelessMCP uses, answered as bytes.
func wireToolsList(t *testing.T, srv *mcp.Server) []json.RawMessage {
	t.Helper()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("tools/list answer does not decode: %v\n%s", err, rec.Body.String())
	}
	return env.Result.Tools
}

// hintPool is the production tool set — the built-in tools and `sealed_call` — over a directory
// with a guest, a pending contact and a contact granted every core permission.
func hintPool() (*Pool, []string) {
	dir := &fakeDirectory{
		tiers: map[string]policy.Tier{"sha256:asked": policy.TierPending, "sha256:alina": policy.TierContact},
		perms: map[string]map[string]bool{"sha256:alina": {
			"message.text": true, "message.media": true, "status.view": true,
			"calendar.availability": true, "calendar.book": true,
		}},
	}
	reg := &Registry{}
	reg.Add(BuiltinEntries(ToolDeps{})...)
	reg.Add(SealedEntries(SealedDeps{})...)
	return NewPool(reg, dir.resolve, 8), []string{"", "sha256:asked", "sha256:alina"}
}

// checkServedHints holds what a caller was served to the table: every tool has exactly the four
// hints, each the value wantProtocolHints gives it, and `seen` records it.
func checkServedHints(t *testing.T, caller string, tools []json.RawMessage, seen map[string]bool) {
	t.Helper()
	for _, raw := range tools {
		name, got := hintsOnTheWire(t, raw)
		want, ok := wantProtocolHints[name]
		if !ok {
			t.Fatalf("caller %q is served %s, which the hint table does not name", caller, name)
		}
		if got != want {
			t.Errorf("caller %q: %s hints (ro, de, id, ow) = %v on the wire, want %v", caller, name, got, want)
		}
		seen[name] = true
	}
}

// Every HDTP tool states its four hints on the wire, with the table's values, on both lists a
// caller can ask for: the plaintext `tools/list` the transport serves at the guest, pending and
// contact tiers, and the one Pool.Dispatch answers inside a sealed envelope. The three tiers
// together serve every tool once, so the table is held to the set in both directions.
func TestEveryHDTPToolStatesItsFourHintsOnTheWire(t *testing.T) {
	pool, callers := hintPool()
	ctx := context.Background()

	plaintext, sealed := map[string]bool{}, map[string]bool{}
	for _, fpr := range callers {
		srv, err := pool.ServerFor(ctx, "acct", fpr)
		if err != nil {
			t.Fatal(err)
		}
		checkServedHints(t, fpr, wireToolsList(t, srv), plaintext)

		inner, err := pool.Dispatch(ctx, "acct", fpr, Payload{Method: "tools/list"})
		if err != nil {
			t.Fatalf("sealed tools/list for %q: %v", fpr, err)
		}
		var list struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(inner, &list); err != nil {
			t.Fatalf("sealed tools/list for %q does not decode: %v\n%s", fpr, err, inner)
		}
		checkServedHints(t, "sealed "+fpr, list.Tools, sealed)
	}
	for name := range wantProtocolHints {
		if !plaintext[name] {
			t.Errorf("%s was served to no caller in plaintext", name)
		}
		if !sealed[name] {
			t.Errorf("%s was served to no caller inside a sealed call", name)
		}
	}
	if len(protocolHints) != len(wantProtocolHints) {
		t.Errorf("hints.go names %d tools, this test %d", len(protocolHints), len(wantProtocolHints))
	}
}

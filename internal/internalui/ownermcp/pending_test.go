package ownermcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

func TestPendingResourceAndAnswerRequest(t *testing.T) {
	e := newEnv(t)
	aa := &integrations.AgentAnswered{Store: e.st, Bus: e.deps.Bus, WaitBudget: 3 * time.Second}
	e.deps.Pending = aa
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	first, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA})
	var start struct {
		Cursor int64 `json:"cursor"`
	}
	if err := json.Unmarshal([]byte(first), &start); err != nil {
		t.Fatalf("first wait: %s", first)
	}

	// a contact's agent-answered call parks, and the agent's wait wakes for it
	entry := integrations.ExposureEntry{Tool: "ask", Mode: integrations.ModeAgent, ExposedName: "ask_me"}
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := aa.Handler(e.acctA, "sha256:bella", "messages_only", entry, nil)(context.Background(),
			&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "ask_me", Arguments: json.RawMessage(`{"q":"lunch?"}`)}})
		done <- res
	}()
	// A starvation threshold, not a latency budget: the wait wakes as the request parks.
	woke, _ := callJSON(t, cs, "wait_for_updates", map[string]any{"account_id": e.acctA, "since": start.Cursor, "timeout_sec": 25})
	if !strings.Contains(woke, `"pending_requests":1`) {
		t.Fatalf("the wait did not report the parked request: %s", woke)
	}

	// the agent lists it (poll parity with the resource), then answers it
	text, isErr := callJSON(t, cs, "list_pending", map[string]any{"account_id": e.acctA})
	if isErr || !strings.Contains(text, `lunch?`) || !strings.Contains(text, `"TrustFlag":"messages_only"`) {
		t.Fatalf("list_pending: %s", text)
	}
	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: URIPending})
	if err != nil || !strings.Contains(rr.Contents[0].Text, "ask_me") {
		t.Fatalf("resource read: %v", err)
	}
	var rows []map[string]any
	_ = json.Unmarshal([]byte(text), &rows)
	id, _ := rows[0]["ID"].(string)
	text, isErr = callJSON(t, cs, "answer_request", map[string]any{
		"account_id": e.acctA, "request_id": id, "result": `{"answer":"yes"}`,
	})
	if isErr || !strings.Contains(text, `"relayed":true`) {
		t.Fatalf("answer_request: %s", text)
	}
	res := <-done
	if res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "yes") {
		t.Fatalf("caller result: %+v", res)
	}
	// scoped token for another account cannot answer it
	cs2, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctB}, nil)
	if _, isErr := callJSON(t, cs2, "answer_request", map[string]any{
		"account_id": e.acctA, "request_id": id, "result": "x",
	}); !isErr {
		t.Fatal("foreign-scoped token answered")
	}
}

// A token narrowed to account B answers another account's request id exactly as it answers an id
// that names nothing, and leaves the request open: the request was read by id alone and its
// account compared after, so "belongs to another account" against "unknown pending request" told
// the token which ids exist on the node.
func TestAnswerRequestAnswersAForeignRequestAsAMissingOne(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.deps.Pending = &integrations.AgentAnswered{Store: e.st, Bus: e.deps.Bus, WaitBudget: time.Second}
	row, err := e.st.InsertPendingRequest(ctx, store.PendingRequest{AccountID: e.acctA, ContactFpr: "sha256:bella",
		Capability: "ask_me", Args: "{}", Status: "open", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctB}, nil)
	foreign, foreignErr := callJSON(t, cs, "answer_request", map[string]any{
		"account_id": e.acctB, "request_id": row.ID, "result": "x",
	})
	missing, missingErr := callJSON(t, cs, "answer_request", map[string]any{
		"account_id": e.acctB, "request_id": "no-such-request", "result": "x",
	})
	if !foreignErr || !missingErr {
		t.Fatalf("not refused: another account's request %q, a missing id %q", foreign, missing)
	}
	if foreign != missing {
		t.Fatalf("told apart: another account's request %q, a missing id %q", foreign, missing)
	}
	if got, err := e.st.GetPendingRequest(ctx, row.ID); err != nil || got.Status != "open" {
		t.Fatalf("the other account's request is now %+v (%v)", got, err)
	}
}

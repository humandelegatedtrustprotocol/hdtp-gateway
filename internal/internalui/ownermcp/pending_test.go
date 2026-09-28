package ownermcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/integrations"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

func TestPendingResourceAndAnswerRequest(t *testing.T) {
	e := newEnv(t)
	aa := &integrations.AgentAnswered{Store: e.st, Bus: e.deps.Bus, WaitBudget: 3 * time.Second}
	e.deps.Pending = aa
	updated := make(chan string, 4)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, &mcp.ClientOptions{
		ResourceUpdatedHandler: func(_ context.Context, r *mcp.ResourceUpdatedNotificationRequest) {
			updated <- r.Params.URI
		},
	})
	if err := cs.Subscribe(context.Background(), &mcp.SubscribeParams{URI: URIPending}); err != nil {
		t.Fatal(err)
	}
	// Subscribe returning is NOT the end of the SEP-2575 handshake: the server
	// still sends subscriptions/acknowledged, and a ResourceUpdated that races
	// into that window is lost by the SDK. Wait the handshake out — the JS
	// agents speak 2025-06-18 (legacy notifications) and never see this race.
	awaitSubscribed(t, e, 1)

	// a contact's agent-answered call parks and signals pact://pending
	entry := integrations.ExposureEntry{Tool: "ask", Mode: integrations.ModeAgent, ExposedName: "ask_me"}
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := aa.Handler(e.acctA, "sha256:bella", "messages_only", entry, nil)(context.Background(),
			&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "ask_me", Arguments: json.RawMessage(`{"q":"lunch?"}`)}})
		done <- res
	}()
	select {
	case uri := <-updated:
		if uri != URIPending {
			t.Fatalf("uri: %s", uri)
		}
	case <-time.After(30 * time.Second):
		// A starvation threshold, not a latency budget. Three seconds passed
		// alone and failed inside `make check`, where the whole suite runs
		// under -race: the signal is prompt when the machine is not saturated,
		// and a longer wait costs nothing when it is.
		t.Fatal("no ResourceUpdated for pact://pending")
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

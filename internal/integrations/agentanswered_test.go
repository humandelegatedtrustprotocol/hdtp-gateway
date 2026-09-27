package integrations

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
)

func aaEnv(t *testing.T) (*AgentAnswered, store.Store, *auditRec, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "aa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	aud := &auditRec{}
	aa := &AgentAnswered{Store: st, Bus: messaging.NewBus(), Audit: aud.fn, WaitBudget: 2 * time.Second}
	return aa, st, aud, a.ID
}

func aaCall(h mcp.ToolHandler, args string) (*mcp.CallToolResult, error) {
	return h(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "ask_me", Arguments: json.RawMessage(args)},
	})
}

func resText(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestConnectedAgentAnswerIsRelayed(t *testing.T) {
	aa, st, aud, acct := aaEnv(t)
	ctx := context.Background()
	entry := ExposureEntry{Tool: "ask", Mode: ModeAgent, ExposedName: "ask_me"}
	events, cancel := aa.Bus.Subscribe(acct)
	defer cancel()

	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := aaCall(aa.Handler(acct, "sha256:bella", "may_instruct", entry, nil), `{"q":"free friday?"}`)
		done <- res
	}()
	// the pending row + bus signal appear; the fake owner-agent answers
	select {
	case e := <-events:
		if e.Kind != messaging.EventPending {
			t.Fatalf("event: %+v", e)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no pending bus event")
	}
	rows, err := st.ListOpenPendingRequests(ctx, acct, time.Now().Unix())
	if err != nil || len(rows) != 1 {
		t.Fatalf("pending rows: %v %d", err, len(rows))
	}
	if rows[0].TrustFlag != "may_instruct" || rows[0].Args != `{"q":"free friday?"}` {
		t.Fatalf("row: %+v", rows[0])
	}
	relayed, err := aa.Answer(ctx, acct, rows[0].ID, `{"answer":"yes, after 3pm"}`)
	if err != nil || !relayed {
		t.Fatalf("answer: relayed=%v err=%v", relayed, err)
	}
	res := <-done
	if res.IsError || !strings.Contains(resText(res), "after 3pm") {
		t.Fatalf("caller got: %q", resText(res))
	}
	if !aud.has("pending_create") || !aud.hasRow("answer_request", "pending:"+rows[0].ID, "ok") {
		t.Fatalf("audit: %v", aud.rows)
	}
	// answered rows leave the open list; double answer refused
	if rows2, _ := st.ListOpenPendingRequests(ctx, acct, time.Now().Unix()); len(rows2) != 0 {
		t.Fatal("answered row still open")
	}
	if _, err := aa.Answer(ctx, acct, rows[0].ID, "again"); err == nil {
		t.Fatal("double answer accepted")
	}
}

func TestNoAgentFallsBackImmediately(t *testing.T) {
	aa, _, aud, acct := aaEnv(t)
	aa.Connected = func(string) bool { return false }
	fallbackHit := false
	fb := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fallbackHit = true
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "mapped says 10:00"}}}, nil
	}
	entry := ExposureEntry{Tool: "ask", Mode: ModeAgent, ExposedName: "ask_me", Fallback: ModeMapped}
	start := time.Now()
	res, err := aaCall(aa.Handler(acct, "sha256:b", "messages_only", entry, fb), `{}`)
	if err != nil || !fallbackHit || resText(res) != "mapped says 10:00" {
		t.Fatalf("fallback: %v %q", err, resText(res))
	}
	if time.Since(start) > time.Second {
		t.Fatal("no-agent path waited the budget")
	}
	if !aud.hasRow("pending_fallback", "capability:ask_me why:no_agent", "ok") {
		t.Fatalf("audit: %v", aud.rows)
	}
	// without a bound fallback: unavailable
	entry2 := ExposureEntry{Tool: "ask", Mode: ModeAgent, ExposedName: "ask_me"}
	res2, _ := aaCall(aa.Handler(acct, "sha256:b", "messages_only", entry2, nil), `{}`)
	if !res2.IsError || !strings.Contains(resText(res2), "unavailable") {
		t.Fatalf("no-fallback: %q", resText(res2))
	}
}

func TestBudgetExpiryRunsFallbackAndLateAnswerIsNotRelayed(t *testing.T) {
	aa, st, aud, acct := aaEnv(t)
	aa.WaitBudget = 150 * time.Millisecond
	entry := ExposureEntry{Tool: "ask", Mode: ModeAgent, ExposedName: "ask_me"}
	res, err := aaCall(aa.Handler(acct, "sha256:b", "messages_only", entry, nil), `{}`)
	if err != nil || !res.IsError || !strings.Contains(resText(res), "unavailable") {
		t.Fatalf("budget expiry: %v %q", err, resText(res))
	}
	// the row is still open (TTL not passed): a LATE answer records, not relays
	rows, _ := st.ListOpenPendingRequests(context.Background(), acct, time.Now().Unix())
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	relayed, err := aa.Answer(context.Background(), acct, rows[0].ID, `{"late":true}`)
	if err != nil || relayed {
		t.Fatalf("late answer: relayed=%v err=%v", relayed, err)
	}
	if !aud.hasRow("answer_request", "pending:"+rows[0].ID, "late") {
		t.Fatalf("late not audited: %v", aud.rows)
	}
	got, _ := st.GetPendingRequest(context.Background(), rows[0].ID)
	if got.Status != "answered" || got.Result != `{"late":true}` {
		t.Fatalf("late answer not recorded: %+v", got)
	}
}

func TestExpiredRequestCannotBeAnswered(t *testing.T) {
	aa, st, _, acct := aaEnv(t)
	clock := time.Unix(1756000000, 0)
	aa.Now = func() time.Time { return clock }
	aa.TTL = time.Minute
	aa.Connected = func(string) bool { return false } // park + immediate fallback
	entry := ExposureEntry{Tool: "ask", Mode: ModeAgent, ExposedName: "ask_me"}
	_, _ = aaCall(aa.Handler(acct, "sha256:b", "messages_only", entry, nil), `{}`)
	rows, _ := st.ListOpenPendingRequests(context.Background(), acct, clock.Unix())
	if len(rows) != 1 {
		t.Fatalf("rows: %d", len(rows))
	}
	clock = clock.Add(2 * time.Minute) // TTL passed
	if _, err := aa.Answer(context.Background(), acct, rows[0].ID, "too late"); err == nil {
		t.Fatal("expired request answered")
	}
	// wrong account refused
	if _, err := aa.Answer(context.Background(), "other", rows[0].ID, "x"); err == nil {
		t.Fatal("cross-account answer accepted")
	}
}

package integrations

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
)

// processAA is one node process's agent-answered service on a shared store file: its own store
// handle, its own bus with its reader running.
func processAA(t *testing.T, path string, migrate bool) (*AgentAnswered, store.Store, *auditRec) {
	t.Helper()
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if migrate {
		if err := st.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	bus := messaging.NewBus(st)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { bus.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	aud := &auditRec{}
	return &AgentAnswered{Store: st, Bus: bus, Audit: aud.fn, WaitBudget: 8 * time.Second}, st, aud
}

// A call held by one node process is answered through another's owner MCP (SPEC §6.8): the
// caller gets the answer, the holding process audits pending_relay, and the answering process
// reports relayed — because the holder said so, not because it hoped. An answer that arrives
// after the holder gave up is recorded and reported late.
func TestAnAnswerGivenOnOneProcessReachesACallHeldByAnother(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	holder, st, holderAudit := processAA(t, path, true)
	answerer, _, answererAudit := processAA(t, path, false)
	a, err := st.CreateAccount(context.Background(), store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	entry := ExposureEntry{Tool: "ask", Mode: ModeAgent, ExposedName: "ask_me"}
	ctx := context.Background()

	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := aaCall(holder.Handler(a.ID, "sha256:bella", "may_instruct", entry, nil), `{"q":"free friday?"}`)
		done <- res
	}()
	var id string
	for deadline := time.Now().Add(5 * time.Second); id == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if rows, err := st.ListOpenPendingRequests(ctx, a.ID, time.Now().Unix()); err == nil && len(rows) == 1 {
			id = rows[0].ID
		}
	}
	if id == "" {
		t.Fatal("the call was never parked")
	}
	relayed, err := answerer.Answer(ctx, a.ID, id, `{"answer":"yes, 3pm"}`)
	if err != nil || !relayed {
		t.Fatalf("an answer on another process was not relayed: %v %v", relayed, err)
	}
	res := <-done
	if res.IsError || !strings.Contains(resText(res), "yes, 3pm") {
		t.Fatalf("the held call answered %+v", res)
	}
	if !holderAudit.hasRow("pending_relay", "pending:"+id, "ok") || !answererAudit.hasRow("answer_request", "pending:"+id, "ok") {
		t.Fatalf("rows: holder %v, answerer %v", holderAudit.rows, answererAudit.rows)
	}

	// The control: nobody holds this one any more (its budget ran out), so the answer is late.
	holder.WaitBudget = 300 * time.Millisecond
	go func() {
		res, _ := aaCall(holder.Handler(a.ID, "sha256:bella", "may_instruct", entry, nil), `{"q":"and saturday?"}`)
		done <- res
	}()
	<-done // the fallback: nobody answered within its budget
	rows, err := st.ListOpenPendingRequests(ctx, a.ID, time.Now().Unix())
	if err != nil || len(rows) != 1 {
		t.Fatalf("open rows: %v %v", rows, err)
	}
	relayed, err = answerer.Answer(ctx, a.ID, rows[0].ID, `{"answer":"no"}`)
	if err != nil || relayed {
		t.Fatalf("an answer nobody held was reported relayed: %v %v", relayed, err)
	}
	if !answererAudit.hasRow("answer_request", "pending:"+rows[0].ID, "late") {
		t.Fatalf("the late answer was not audited late: %v", answererAudit.rows)
	}
}

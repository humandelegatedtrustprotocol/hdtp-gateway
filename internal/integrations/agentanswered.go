package integrations

// Agent-answered mode (SPEC §6.8): a call with no API behind it is parked as a
// pending_requests row, signaled to the owner's agent over pact://pending, and
// held open for a synchronous wait budget. An answer inside the budget is
// relayed; budget expiry or no connected agent runs the fallback chain (the
// exposure's fallback mode, else `unavailable`). The TTL only bounds how long a
// LATE answer may still land — recorded and audited, no longer relayed.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
)

const (
	// DefaultWaitBudget holds the caller's call open (SPEC §6.8).
	DefaultWaitBudget = 30 * time.Second
	// DefaultPendingTTL bounds how long the row accepts a late answer.
	DefaultPendingTTL = 10 * time.Minute
)

type AgentAnswered struct {
	Store store.IntegrationStore
	Bus   *messaging.Bus
	Audit func(action, resource, outcome string)
	// Connected reports whether an owner-agent session is live for the account;
	// nil assumes connected (the wait budget then governs alone).
	Connected  func(accountID string) bool
	WaitBudget time.Duration
	TTL        time.Duration
	Now        func() time.Time

	mu      sync.Mutex
	waiters map[string]chan string // request id → result JSON
}

func (a *AgentAnswered) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *AgentAnswered) budget() time.Duration {
	if a.WaitBudget > 0 {
		return a.WaitBudget
	}
	return DefaultWaitBudget
}

func (a *AgentAnswered) ttl() time.Duration {
	if a.TTL > 0 {
		return a.TTL
	}
	return DefaultPendingTTL
}

func (a *AgentAnswered) audit(action, resource, outcome string) {
	if a.Audit != nil {
		a.Audit(action, resource, outcome)
	}
}

func (a *AgentAnswered) register(id string) chan string {
	ch := make(chan string, 1)
	a.mu.Lock()
	if a.waiters == nil {
		a.waiters = map[string]chan string{}
	}
	a.waiters[id] = ch
	a.mu.Unlock()
	return ch
}

func (a *AgentAnswered) unregister(id string) {
	a.mu.Lock()
	delete(a.waiters, id)
	a.mu.Unlock()
}

// Handler serves one agent-answered exposure for one caller. fallback is the
// entry's bound fallback-mode handler (nil = none → `unavailable`).
func (a *AgentAnswered) Handler(accountID, contactFpr, trustFlag string, entry ExposureEntry, fallback mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		row, err := a.Store.InsertPendingRequest(ctx, store.PendingRequest{
			AccountID: accountID, ContactFpr: contactFpr, Capability: entry.ExposedName,
			Args: string(req.Params.Arguments), TrustFlag: trustFlag,
			CreatedAt: a.now().Unix(), ExpiresAt: a.now().Add(a.ttl()).Unix(),
		})
		if err != nil {
			return errResult("unavailable"), nil
		}
		ch := a.register(row.ID)
		defer a.unregister(row.ID)
		a.Bus.Publish(messaging.Event{Kind: messaging.EventPending, AccountID: accountID, ContactFpr: contactFpr})
		a.audit("pending_create", "account:"+accountID+" pending:"+row.ID, "ok")

		if a.Connected != nil && !a.Connected(accountID) {
			return a.fallbackResult(ctx, accountID, req, entry, fallback, "no_agent")
		}
		t := time.NewTimer(a.budget())
		defer t.Stop()
		select {
		case result := <-ch:
			a.audit("pending_relay", "account:"+accountID+" pending:"+row.ID, "ok")
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}, nil
		case <-t.C:
			return a.fallbackResult(ctx, accountID, req, entry, fallback, "budget_expired")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (a *AgentAnswered) fallbackResult(ctx context.Context, accountID string, req *mcp.CallToolRequest, entry ExposureEntry, fallback mcp.ToolHandler, why string) (*mcp.CallToolResult, error) {
	if entry.Fallback != "" && fallback != nil {
		a.audit("pending_fallback", "account:"+accountID+" capability:"+entry.ExposedName+" why:"+why, "ok")
		return fallback(ctx, req)
	}
	a.audit("pending_fallback", "account:"+accountID+" capability:"+entry.ExposedName+" why:"+why, "unavailable")
	return errResult("unavailable"), nil
}

// Answer records the agent's result (owner-MCP answer_request, SPEC §6.8):
// atomic against expiry; relays to the waiting caller when one is still there.
// A late answer is recorded and audited but no longer relayed.
func (a *AgentAnswered) Answer(ctx context.Context, accountID, requestID, result string) (relayed bool, err error) {
	row, err := a.Store.GetPendingRequest(ctx, requestID)
	if err != nil {
		return false, fmt.Errorf("integrations: unknown pending request")
	}
	if row.AccountID != accountID {
		return false, fmt.Errorf("integrations: pending request belongs to another account")
	}
	nowUnix := a.now().Unix()
	ok, err := a.Store.AnswerPendingRequest(ctx, requestID, result, nowUnix, nowUnix)
	if err != nil {
		return false, err
	}
	if !ok {
		a.audit("answer_request", "account:"+row.AccountID+" pending:"+requestID, "error")
		return false, fmt.Errorf("integrations: request is expired or already answered")
	}
	a.mu.Lock()
	ch := a.waiters[requestID]
	a.mu.Unlock()
	if ch != nil {
		select {
		case ch <- result:
			a.audit("answer_request", "account:"+row.AccountID+" pending:"+requestID, "ok")
			return true, nil
		default:
		}
	}
	a.audit("answer_request", "account:"+row.AccountID+" pending:"+requestID, "late")
	return false, nil
}

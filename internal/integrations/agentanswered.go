package integrations

// Agent-answered mode (SPEC §6.8): a call with no API behind it is parked as a
// pending_requests row, which the owner's agent learns of through wait_for_updates
// and list_pending, and held open for a synchronous wait budget. An answer inside the
// budget is relayed; budget expiry or no attached agent runs the fallback chain (the
// exposure's fallback mode, else `unavailable`). The TTL only bounds how long a
// LATE answer may still land — recorded and audited, no longer relayed.
//
// The call and the answer may reach different node processes sharing the store. The
// row is where the answer lives; the bus, whose events every process hears (SPEC
// §7.8), only says "look": the waiting call re-reads its row on every event for its
// account, and says it relayed an answer with an EventRelayed that the answering
// process waits for.

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
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
}

// RelayWait is how long Answer waits for the held call to say it relayed the answer before it
// reports the answer late: long enough for the answer to reach a call held by another process and
// that process's word to come back (two reads of the change log, 250 ms apart at most).
const RelayWait = 3 * time.Second

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
		// Listening before the request is announced: an answer given at once still wakes it.
		evs, stop := a.Bus.Subscribe(accountID)
		defer stop()
		a.Bus.Publish(messaging.Event{Kind: messaging.EventPending, AccountID: accountID, ContactFpr: contactFpr, Ref: row.ID})
		a.audit("pending_create", "account:"+accountID+" pending:"+row.ID, "ok")

		if a.Connected != nil && !a.Connected(accountID) {
			return a.fallbackResult(ctx, accountID, req, entry, fallback, "no_agent")
		}
		t := time.NewTimer(a.budget())
		defer t.Stop()
		for {
			select {
			case <-evs:
				// Any event for the account is a reason to look: the one that answered this call
				// may have been dropped by a full subscriber, and the row is the truth.
				cur, err := a.Store.GetPendingRequest(ctx, row.ID)
				if err != nil || cur.Status != "answered" {
					continue
				}
				a.audit("pending_relay", "account:"+accountID+" pending:"+row.ID, "ok")
				a.Bus.Publish(messaging.Event{Kind: messaging.EventRelayed, AccountID: accountID, Ref: row.ID})
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: cur.Result}}}, nil
			case <-t.C:
				return a.fallbackResult(ctx, accountID, req, entry, fallback, "budget_expired")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
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
// atomic against expiry; relays to the waiting caller when one is still there, in
// this process or another on the store, and reports relayed only when the held call
// says it relayed it (within RelayWait). A late answer is recorded and audited but no
// longer relayed.
func (a *AgentAnswered) Answer(ctx context.Context, accountID, requestID, result string) (relayed bool, err error) {
	row, err := a.Store.GetPendingRequest(ctx, requestID)
	if err != nil {
		return false, fmt.Errorf("integrations: unknown pending request")
	}
	if row.AccountID != accountID {
		return false, fmt.Errorf("integrations: pending request belongs to another account")
	}
	// Listening before the answer is written: the held call's word may come back at once.
	evs, stop := a.Bus.Subscribe(row.AccountID)
	defer stop()
	nowUnix := a.now().Unix()
	ok, err := a.Store.AnswerPendingRequest(ctx, requestID, result, nowUnix, nowUnix)
	if err != nil {
		return false, err
	}
	if !ok {
		a.audit("answer_request", "account:"+row.AccountID+" pending:"+requestID, "error")
		return false, fmt.Errorf("integrations: request is expired or already answered")
	}
	a.Bus.Publish(messaging.Event{Kind: messaging.EventAnswered, AccountID: row.AccountID, Ref: requestID})
	t := time.NewTimer(RelayWait)
	defer t.Stop()
	for {
		select {
		case e := <-evs:
			if e.Kind != messaging.EventRelayed || e.Ref != requestID {
				continue
			}
			a.audit("answer_request", "account:"+row.AccountID+" pending:"+requestID, "ok")
			return true, nil
		case <-t.C:
			a.audit("answer_request", "account:"+row.AccountID+" pending:"+requestID, "late")
			return false, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

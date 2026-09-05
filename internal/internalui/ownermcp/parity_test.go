package ownermcp

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
)

// AC (P10-08f): a token scoped to one account must not read another account's
// audit rows. `audit_query` was the only parity tool that never called `allow`,
// so any token read the whole node's chain — and PLAN.md recorded the opposite
// as P9-01's acceptance criterion.
func TestAuditQueryNeverLeavesTheIdentitysAccounts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	rows := []store.AuditRow{
		{AccountID: e.acctA, ActorKind: "owner", Action: "work_only", Resource: "r", Outcome: "ok"},
		{AccountID: e.acctB, ActorKind: "owner", Action: "home_only", Resource: "r", Outcome: "ok"},
		{AccountID: "", ActorKind: "system", Action: "node_level", Resource: "r", Outcome: "ok"},
	}
	extra := Extra{
		Audit: func(_ context.Context, _ string, limit int, permit func(string) bool) ([]store.AuditRow, error) {
			var kept []store.AuditRow
			for _, r := range rows {
				if permit == nil || permit(r.AccountID) {
					kept = append(kept, r)
				}
			}
			return kept, nil
		},
	}

	// A token scoped to "work" sees work and node-level rows, never "home".
	srv := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner, AccountID: e.acctA})
	body := callParity(t, ctx, srv, "audit_query", map[string]any{})
	if !strings.Contains(body, "work_only") {
		t.Fatalf("scoped token lost its own account's rows: %s", body)
	}
	if strings.Contains(body, "home_only") {
		t.Fatalf("scoped token read another account's audit rows: %s", body)
	}
	// A row this node cannot attribute to an account is one a NARROWED token
	// must not be shown — see TestScopedTokenCannotReadNodeLevelAuditRows for
	// why treating "no account" as public is how the scoping became vacuous.
	if strings.Contains(body, "node_level") {
		t.Fatalf("a scoped token saw an unattributable row: %s", body)
	}

	// An unscoped owner administers both, and sees both.
	srv2 := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner})
	body2 := callParity(t, ctx, srv2, "audit_query", map[string]any{})
	if !strings.Contains(body2, "work_only") || !strings.Contains(body2, "home_only") {
		t.Fatalf("unscoped owner lost rows they administer: %s", body2)
	}
}

// callParity drives one tool on a parity-equipped server.
func callParity(t *testing.T, ctx context.Context, srv *mcp.Server, tool string, args map[string]any) string {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Wait()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if len(res.Content) == 0 {
		return ""
	}
	tc, _ := res.Content[0].(*mcp.TextContent)
	if tc == nil {
		return ""
	}
	return tc.Text
}

// AC (P10-08e): every owner-MCP tool call is audited, including reads and
// refusals (SPEC §8.7).
//
// Individual tools logged their own mutations and read-only calls logged
// nothing at all, so an owner reviewing the trail could not see what a token had
// LOOKED at — and a token that only reads is still a token that was used.
func TestEveryOwnerMCPCallIsAudited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var logged []string
	extra := Extra{
		Log: func(action, resource, outcome string) {
			logged = append(logged, action+" "+resource+" "+outcome)
		},
	}
	srv := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner})

	// A read-only call.
	_ = callParity(t, ctx, srv, "list_accounts", map[string]any{})
	// …and one that must be refused: an account this identity does not admin.
	_ = callParity(t, ctx, srv, "get_inbox", map[string]any{"account_id": "not-mine"})

	var sawRead, sawRefusal bool
	for _, l := range logged {
		if strings.HasPrefix(l, "owner_mcp_call tool:list_accounts") {
			sawRead = true
		}
		if strings.HasPrefix(l, "owner_mcp_call tool:get_inbox") && strings.HasSuffix(l, "refused") {
			sawRefusal = true
		}
	}
	if !sawRead {
		t.Errorf("a read-only call left no audit trail: %v", logged)
	}
	if !sawRefusal {
		t.Errorf("a refusal was not audited as one: %v", logged)
	}
}

// AC (P10-08h): §8.4's "integration management" row exists, and an agent sees
// what is EXPOSED rather than what an upstream offers.
func TestIntegrationToolsShowExposureNotTheUpstreamCatalog(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var published []string
	extra := Extra{
		Integrations: func(_ context.Context, accountID string) ([]IntegrationView, error) {
			if accountID != e.acctA {
				t.Fatalf("asked about the wrong account: %s", accountID)
			}
			return []IntegrationView{{
				ID: "i1", Slug: "cal", Status: "ok", Auth: "oauth",
				Exposed: []string{"cal_find"}, Stale: []string{"cal_book"},
			}}, nil
		},
		SetExposure: func(_ context.Context, accountID, integrationID string, tools []string) error {
			if accountID != e.acctA {
				t.Fatalf("set_exposure reached the implementation with account %q", accountID)
			}
			published = tools
			return nil
		},
		Log: func(string, string, string) {},
	}
	srv := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner})

	body := callParity(t, ctx, srv, "list_integrations", map[string]any{"account_id": e.acctA})
	for _, want := range []string{`"slug":"cal"`, `"exposed":["cal_find"]`, `"stale":["cal_book"]`} {
		if !strings.Contains(body, want) {
			t.Errorf("list_integrations missing %s: %s", want, body)
		}
	}
	// No credential, endpoint or upstream schema may travel to an agent.
	for _, forbidden := range []string{"client_secret", "Bearer", "endpoint"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("an agent was shown %q: %s", forbidden, body)
		}
	}

	// Narrowing to nothing is how an agent withdraws an integration, so an
	// empty list must be APPLIED, not read as a missing argument.
	published = nil
	out := callParity(t, ctx, srv, "set_exposure", map[string]any{
		"account_id": e.acctA, "integration_id": "i1", "tools": []string{},
	})
	if !strings.Contains(out, `"status":"ok"`) {
		t.Fatalf("emptying an exposure set was refused: %s", out)
	}
	if published == nil || len(published) != 0 {
		t.Fatalf("the empty list did not reach the publisher: %v", published)
	}

	// Another identity's account is refused, like every other tool here.
	denied := callParity(t, ctx, srv, "set_exposure", map[string]any{
		"account_id": "not-mine", "integration_id": "i1", "tools": []string{"x"},
	})
	if !strings.Contains(denied, "permission_denied") {
		t.Fatalf("an unadministered account was accepted: %s", denied)
	}
}

// AC (P11-08): set_exposure must not act on an integration outside the account
// it authorized.
//
// It gated on the caller-supplied `account_id` and then acted on a
// caller-supplied `integration_id` that was never checked against it — so a
// token scoped to one account could name its own account and ANOTHER account's
// integration, and republish or withdraw that account's entire served surface.
// That is the same scoping hole P10-08f closed for audit_query, one tool over.
func TestSetExposureCannotReachAnotherAccountsIntegration(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// The implementation is the real one's contract: refuse when the integration
	// does not belong to the account the caller was authorized for.
	var acted []string
	extra := Extra{
		SetExposure: func(_ context.Context, accountID, integrationID string, tools []string) error {
			if integrationID == "belongs-to-B" && accountID != e.acctB {
				return errWrongAccount
			}
			acted = append(acted, accountID+"/"+integrationID)
			return nil
		},
		Log: func(string, string, string) {},
	}
	// A token scoped to account A.
	srv := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner, AccountID: e.acctA})

	// Naming its OWN account with ANOTHER account's integration must not act.
	out := callParity(t, ctx, srv, "set_exposure", map[string]any{
		"account_id": e.acctA, "integration_id": "belongs-to-B", "tools": []string{"x"},
	})
	if len(acted) != 0 {
		t.Fatalf("a scoped token republished another account's integration: %v", acted)
	}
	if !strings.Contains(out, "bad_request") && !strings.Contains(out, "permission_denied") {
		t.Fatalf("the cross-account attempt was not refused: %s", out)
	}

	// Its own integration still works.
	callParity(t, ctx, srv, "set_exposure", map[string]any{
		"account_id": e.acctA, "integration_id": "belongs-to-A", "tools": []string{"x"},
	})
	if len(acted) != 1 {
		t.Fatalf("a scoped token could not manage its own integration: %v", acted)
	}
}

var errWrongAccount = &wrongAccountErr{}

type wrongAccountErr struct{}

func (*wrongAccountErr) Error() string { return "that integration belongs to another account" }

// AC (P11-09): a token scoped to one account cannot read node-level audit rows.
//
// Every row was written with an empty account_id, and audit_query permitted a
// row when it had no account — so the scoping added by P10-08f permitted
// everything. "No account" and "an account you may not see" are
// indistinguishable to the filter, so a narrowed token gets neither.
func TestScopedTokenCannotReadNodeLevelAuditRows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rows := []store.AuditRow{
		{AccountID: e.acctA, ActorKind: "owner", Action: "work_only", Outcome: "ok"},
		{AccountID: "", ActorKind: "system", Action: "node_level", Outcome: "ok"},
	}
	extra := Extra{Audit: func(_ context.Context, _ string, limit int, permit func(string) bool) ([]store.AuditRow, error) {
		var kept []store.AuditRow
		for _, r := range rows {
			if permit == nil || permit(r.AccountID) {
				kept = append(kept, r)
			}
		}
		return kept, nil
	}}

	scoped := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner, AccountID: e.acctA})
	body := callParity(t, ctx, scoped, "audit_query", map[string]any{})
	if strings.Contains(body, "node_level") {
		t.Fatalf("a token scoped to one account read a row it cannot attribute: %s", body)
	}
	if !strings.Contains(body, "work_only") {
		t.Fatalf("a scoped token lost its own account's rows: %s", body)
	}

	// An unscoped owner administers the node and sees them.
	all := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner})
	body2 := callParity(t, ctx, all, "audit_query", map[string]any{})
	if !strings.Contains(body2, "node_level") {
		t.Fatalf("an unscoped owner lost node-level rows: %s", body2)
	}
}

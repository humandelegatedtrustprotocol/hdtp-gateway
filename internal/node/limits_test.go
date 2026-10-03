package node

// The node's budgets are the limits sidecar's to decide (internal/limits, cmd/hdtp-limitd): these
// hold that each door the node has for one reaches the real sidecar — the pending-request cap on a
// stranger's request, each integration's own cap, and a sidecar that is down — with numbers of their
// own, so nothing passes by agreeing with a default.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
)

func TestAStrangersRequestIsHeldToTheSidecarsPendingCap(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	rules := limitstest.DefaultRules(t)
	rules.PendingInCap = 2
	e.limits = limitstest.Start(t, rules)
	n, err := New(context.Background(), e.options())
	if err != nil {
		t.Fatal(err)
	}
	cm := n.accounts[acct.ID].cm
	ctx := context.Background()
	ask := func(i int) error {
		w := testid.NewWallet(t, fmt.Sprintf("Stranger%d", i))
		h := w.Issue(t, fmt.Sprintf("https://s%d.example/a/s/mcp", i))
		p := contacts.Proof{Fingerprint: w.Fpr, SPKI: h.Key.Public().SPKI, Endpoint: h.Endpoint, Leaf: h.LeafDER}
		return cm.RequestContactAs(ctx, acct.ID, h.Card(fmt.Sprintf("Stranger %d", i), "required"), "", p)
	}
	for i := range int(rules.PendingInCap) {
		if err := ask(i); err != nil {
			t.Fatalf("request %d, under the cap: %v", i+1, err)
		}
	}
	if err := ask(99); !errors.Is(err, contacts.ErrRequestsFull) {
		t.Fatalf("a request past the sidecar's cap of %v: %v, want ErrRequestsFull", rules.PendingInCap, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.Contains(strings.Join(e.rows, "\n"), "rate_limited account:"+acct.ID+" bucket:pending_in refused") {
		t.Fatalf("the refusal was not audited with its account and its bucket: %v", e.rows)
	}
}

func TestAnIntegrationsCallsAreHeldToItsOwnCapPerContact(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	rules := limitstest.DefaultRules(t)
	rules.IntegrationCallsPerHour = 3
	e.limits = limitstest.Start(t, rules)
	n, err := New(context.Background(), e.options())
	if err != nil {
		t.Fatal(err)
	}
	reached := 0
	h := n.IntegrationBudget(acct.ID, "int-1", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		reached++
		return &mcp.CallToolResult{}, nil
	})
	as := func(root string) context.Context {
		return public.WithCaller(context.Background(), policy.Caller{AccountID: acct.ID, Fingerprint: root, Tier: policy.TierContact})
	}
	for i := range int(rules.IntegrationCallsPerHour) {
		if res, _ := h(as("sha256:a"), &mcp.CallToolRequest{}); res.IsError {
			t.Fatalf("call %d, under the cap, was refused", i+1)
		}
	}
	res, _ := h(as("sha256:a"), &mcp.CallToolRequest{})
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"code":"rate_limited","retry_after":`) {
		t.Fatalf("a call past the cap was answered %+v, want rate_limited with its wait", res)
	}
	if reached != int(rules.IntegrationCallsPerHour) {
		t.Fatalf("the upstream was reached %d times, want %v: a refused call reached it", reached, rules.IntegrationCallsPerHour)
	}
	// Per contact: another contact, and the same contact at another integration, are untouched.
	if res, _ := h(as("sha256:b"), &mcp.CallToolRequest{}); res.IsError {
		t.Fatal("another contact's first call was refused")
	}
	other := n.IntegrationBudget(acct.ID, "int-2", func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	if res, _ := other(as("sha256:a"), &mcp.CallToolRequest{}); res.IsError {
		t.Fatal("the same contact's first call to another integration was refused")
	}
	// A sidecar that is down: nothing reaches the upstream, and the answer is unavailable.
	e.limits.Stop()
	before := reached
	if res, _ := h(as("sha256:c"), &mcp.CallToolRequest{}); !res.IsError || res.Content[0].(*mcp.TextContent).Text != `{"code":"unavailable"}` || reached != before {
		t.Fatalf("with the sidecar down an integration call was answered %+v (reached %d)", res, reached-before)
	}
}

func TestEveryBudgetIsRefusedUnavailableWhileTheSidecarIsDown(t *testing.T) {
	e, accounts := newEnv(t, "alice")
	acct := accounts[0]
	n, err := New(context.Background(), e.options())
	if err != nil {
		t.Fatal(err)
	}
	edge := public.WithFacts(context.Background(), public.TransportFacts{RemoteIP: "203.0.113.7"})
	if r := n.consumeBudget(edge, acct.ID, public.ChargeSource); r != nil {
		t.Fatalf("the control, with the sidecar answering: %+v", r)
	}
	if err := n.LimitsAnswer(context.Background()); err != nil {
		t.Fatalf("the control: %v", err)
	}
	e.limits.Stop()
	r := n.consumeBudget(edge, acct.ID, public.ChargeSource)
	if r == nil || !r.Unavailable || r.Code() != "unavailable" {
		t.Fatalf("with the sidecar down a call was %+v, want refused unavailable", r)
	}
	if err := n.LimitsAnswer(context.Background()); err == nil || !strings.Contains(err.Error(), e.limits.Path) {
		t.Fatalf("with the sidecar down the node reports %v, want it named", err)
	}
	e.mu.Lock()
	rows := strings.Join(e.rows, "\n")
	e.mu.Unlock()
	if !strings.Contains(rows, "limits_unavailable account:"+acct.ID) {
		t.Fatalf("the refusal was not audited: %s", rows)
	}
	e.limits.Restart(t)
	if r := n.consumeBudget(edge, acct.ID, public.ChargeSource); r != nil {
		t.Fatalf("after the sidecar came back: %+v", r)
	}
}

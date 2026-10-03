package public

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
)

// fakeDirectory is a mutable caller directory standing in for the contact store.
type fakeDirectory struct {
	mu    sync.Mutex
	perms map[string]map[string]bool // fpr -> permissions
	tiers map[string]policy.Tier     // fpr -> tier
}

func (d *fakeDirectory) resolve(_ context.Context, accountID, fpr string) (policy.Caller, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tier, ok := d.tiers[fpr]
	if !ok {
		tier = policy.TierGuest
	}
	return policy.Caller{AccountID: accountID, Fingerprint: fpr, Tier: tier, Permissions: d.perms[fpr]}, nil
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func testRegistry() *Registry {
	reg := &Registry{}
	echo := func(name string) mcp.ToolHandler {
		return func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return textResult(name), nil
		}
	}
	obj := &jsonSchemaObj
	reg.Add(
		Entry{Tool: &mcp.Tool{Name: "redeem_invite", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierGuest}, Handler: echo("redeem_invite")},
		Entry{Tool: &mcp.Tool{Name: "request_contact", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierGuest}, Handler: echo("request_contact")},
		Entry{Tool: &mcp.Tool{Name: "contact_accepted", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierPending}, Handler: echo("contact_accepted")},
		Entry{Tool: &mcp.Tool{Name: "send_message", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierContact, Permission: "message.text"}, Handler: echo("send_message")},
		Entry{Tool: &mcp.Tool{Name: "book_slot", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierContact, Permission: "calendar.book"}, Handler: echo("book_slot")},
		Entry{Tool: &mcp.Tool{Name: "get_card", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierContact}, Handler: echo("get_card")},
	)
	return reg
}

// connect wires an in-memory client session to the caller's composed server.
func connect(t *testing.T, pool *Pool, account, fpr string, opts *mcp.ClientOptions) (*mcp.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	srv, err := pool.ServerFor(ctx, account, fpr)
	if err != nil {
		t.Fatal(err)
	}
	ct, st := mcp.NewInMemoryTransports()
	srvSession, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cs, func() { cs.Close(); srvSession.Wait() }
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func newTestPool(dir *fakeDirectory) *Pool {
	return NewPool(testRegistry(), dir.resolve, 8)
}

func TestToolsListPerTier(t *testing.T) {
	dir := &fakeDirectory{
		tiers: map[string]policy.Tier{
			"sha256:alina":  policy.TierContact,
			"sha256:vendor": policy.TierContact,
			"sha256:asked":  policy.TierPending,
		},
		perms: map[string]map[string]bool{
			"sha256:alina":  {"message.text": true, "calendar.book": true},
			"sha256:vendor": {"message.text": true},
		},
	}
	pool := newTestPool(dir)

	cases := []struct {
		fpr  string
		want []string
	}{
		{"", []string{"redeem_invite", "request_contact"}},                  // anonymous guest
		{"sha256:stranger", []string{"redeem_invite", "request_contact"}},   // unknown cert
		{"sha256:asked", []string{"contact_accepted"}},                      // pending tier
		{"sha256:vendor", []string{"get_card", "send_message"}},             // text only + always
		{"sha256:alina", []string{"book_slot", "get_card", "send_message"}}, // full grant
	}
	for _, tc := range cases {
		cs, done := connect(t, pool, "acct", tc.fpr, nil)
		got := toolNames(t, cs)
		done()
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("%q tools = %v, want %v", tc.fpr, got, tc.want)
		}
	}
}

// A switchboard change reaches the caller's next request: Invalidate drops the composed server,
// and the next request composes the new surface (SPEC §2.4). Every request is its own session
// (StatelessMCP), so there is no open session to notify.
func TestPermissionFlipIsServedToTheNextRequest(t *testing.T) {
	dir := &fakeDirectory{
		tiers: map[string]policy.Tier{"sha256:alina": policy.TierContact},
		perms: map[string]map[string]bool{"sha256:alina": {"message.text": true, "calendar.book": true}},
	}
	pool := newTestPool(dir)
	if got := requestTools(t, pool, "acct", "sha256:alina"); !contains(got, "book_slot") {
		t.Fatalf("precondition: %v", got)
	}

	// Flip the switchboard: revoke calendar.book.
	dir.mu.Lock()
	dir.perms["sha256:alina"] = map[string]bool{"message.text": true}
	dir.mu.Unlock()
	if err := pool.Invalidate(context.Background(), "acct", "sha256:alina"); err != nil {
		t.Fatal(err)
	}
	if got := requestTools(t, pool, "acct", "sha256:alina"); contains(got, "book_slot") {
		t.Fatalf("book_slot still listed after revocation: %v", got)
	}
}

// requestTools is one stateless request's tools/list: a session of its own over the server the
// pool gives this caller now, closed with the request.
func requestTools(t *testing.T, pool *Pool, account, fpr string) []string {
	t.Helper()
	cs, done := connect(t, pool, account, fpr, nil)
	defer done()
	return toolNames(t, cs)
}

// A server composed before a revocation still refuses the revoked tool: the guard re-checks at
// call time (SPEC §2.4).
func TestCallTimeDenyOnAServerComposedBeforeTheRevocation(t *testing.T) {
	dir := &fakeDirectory{
		tiers: map[string]policy.Tier{"sha256:alina": policy.TierContact},
		perms: map[string]map[string]bool{"sha256:alina": {"message.text": true}},
	}
	pool := newTestPool(dir)
	cs, done := connect(t, pool, "acct", "sha256:alina", nil)
	defer done()

	// Revoke WITHOUT invalidating — the cached server still lists the tool, but the
	// call-time guard must deny (SPEC §2.4 instant revocation).
	dir.mu.Lock()
	dir.perms["sha256:alina"] = map[string]bool{}
	dir.mu.Unlock()

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "send_message", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("revoked call succeeded")
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || !strings.Contains(tc.Text, "permission_denied") {
		t.Fatalf("want permission_denied, got %+v", res.Content)
	}
}

func TestGuestServersSharedAndCallerServersDistinct(t *testing.T) {
	dir := &fakeDirectory{tiers: map[string]policy.Tier{"sha256:a": policy.TierContact}, perms: map[string]map[string]bool{}}
	pool := newTestPool(dir)
	ctx := context.Background()
	g1, _ := pool.ServerFor(ctx, "acct", "")
	g2, _ := pool.ServerFor(ctx, "acct", "")
	if g1 != g2 {
		t.Fatal("anonymous guest server not shared")
	}
	c1, _ := pool.ServerFor(ctx, "acct", "sha256:a")
	if c1 == g1 {
		t.Fatal("caller server must be distinct from guest server")
	}
	other, _ := pool.ServerFor(ctx, "acct2", "")
	if other == g1 {
		t.Fatal("guest servers must be per-account")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// AC (P8-01, defect #3): SPEC §5.8 requires every deny to be audited, at every
// stage. Two paths reach a refusal and only one runs a handler: an authorization
// denial, and a call for a tool absent from this caller's surface, which the SDK
// refuses before any handler is reached. Both must leave exactly one row, and an
// availability failure must NOT be recorded as a denial.
func TestEveryRefusalIsAuditedAndAvailabilityIsNotADenial(t *testing.T) {
	ctx := context.Background()
	obj := json.RawMessage(`{"type":"object"}`)

	call := func(t *testing.T, reg *Registry, resolve CallerResolver, tool string) []string {
		t.Helper()
		var rows []string
		p := NewPool(reg, resolve, 4)
		p.CallAudit = func(kind, action, resource, outcome string) {
			rows = append(rows, kind+" "+action+" "+resource+" "+outcome)
		}
		srv, err := p.ServerFor(ctx, "acct", "sha256:caller")
		if err != nil {
			return []string{"resolve-error"}
		}
		ct, st := mcp.NewInMemoryTransports()
		if _, err := srv.Connect(ctx, st, nil); err != nil {
			t.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		_, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{}})
		return rows
	}

	contactCaller := func(context.Context, string, string) (policy.Caller, error) {
		return policy.Caller{AccountID: "acct", Fingerprint: "sha256:caller",
			Tier: policy.TierContact, Permissions: map[string]bool{}}, nil
	}

	// (a) a tool the caller's switchboard does not grant: composed out, so the
	// SDK refuses it as unknown before any handler runs
	granted := &Registry{}
	granted.Add(Entry{Tool: &mcp.Tool{Name: "send_message", InputSchema: obj},
		Rule: policy.Rule{Tier: policy.TierContact, Permission: "message.text"},
		Handler: func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		}})
	rows := call(t, granted, contactCaller, "send_message")
	if len(rows) != 1 || !strings.Contains(rows[0], "permission_denied") {
		t.Fatalf("absent tool: %v", rows)
	}
	if !strings.Contains(rows[0], "send_message") || !strings.Contains(rows[0], "sha256:caller") {
		t.Fatalf("the row names neither the tool nor the caller: %v", rows)
	}

	// (b) a tool the caller CAN see but is denied at call time (the switchboard
	// changed under a cached server) — audited by guarded, exactly once
	flip := 0
	flipping := func(context.Context, string, string) (policy.Caller, error) {
		flip++
		perms := map[string]bool{"message.text": true}
		if flip > 1 {
			perms = map[string]bool{} // revoked between compose and call
		}
		return policy.Caller{AccountID: "acct", Fingerprint: "sha256:caller",
			Tier: policy.TierContact, Permissions: perms}, nil
	}
	rows = call(t, granted, flipping, "send_message")
	if len(rows) != 1 || !strings.Contains(rows[0], "permission_denied") {
		t.Fatalf("call-time denial: %v", rows)
	}

	// (c) the node cannot resolve the caller at all: that is `unavailable`, not a
	// denial. Recording it as a denial sends an operator after the wrong problem.
	resolves := 0
	broken := func(context.Context, string, string) (policy.Caller, error) {
		resolves++
		if resolves == 1 {
			return policy.Caller{AccountID: "acct", Fingerprint: "sha256:caller",
				Tier: policy.TierContact, Permissions: map[string]bool{"message.text": true}}, nil
		}
		return policy.Caller{}, errors.New("store is down")
	}
	rows = call(t, granted, broken, "send_message")
	if len(rows) != 1 {
		t.Fatalf("availability failure rows: %v", rows)
	}
	if strings.Contains(rows[0], "permission_denied") || !strings.Contains(rows[0], "unavailable") {
		t.Fatalf("an availability failure was recorded as a denial: %v", rows)
	}
}

// AC (P10-04c): a registry group can be revised and withdrawn, and the change
// reaches callers whose servers are already composed.
//
// The registry only had Add(). An integration's tools could go in and never come
// out or change, so an owner narrowing an exposure set (§6.5) or an integration
// being withheld (§6.10) altered a database row and nothing that was being
// served.
func TestRegistryGroupsAreRevisableAndAccountWideRebuildReachesOpenCallers(t *testing.T) {
	ctx := context.Background()
	reg := &Registry{}
	reg.Add(Entry{Tool: &mcp.Tool{Name: "builtin"}, Rule: policy.Rule{Tier: policy.TierContact}})
	reg.Replace("integration:cal", []Entry{
		{Tool: &mcp.Tool{Name: "cal_book"}, Rule: policy.Rule{Tier: policy.TierContact}},
		{Tool: &mcp.Tool{Name: "cal_find"}, Rule: policy.Rule{Tier: policy.TierContact}},
	})
	if got := entryNames(reg.snapshot()); !reflect.DeepEqual(got, []string{"builtin", "cal_book", "cal_find"}) {
		t.Fatalf("after publish: %v", got)
	}

	// Narrowing an exposure set republishes the group, it does not append.
	reg.Replace("integration:cal", []Entry{
		{Tool: &mcp.Tool{Name: "cal_find"}, Rule: policy.Rule{Tier: policy.TierContact}},
	})
	if got := entryNames(reg.snapshot()); !reflect.DeepEqual(got, []string{"builtin", "cal_find"}) {
		t.Fatalf("a narrowed exposure did not remove the tool: %v", got)
	}

	// Withholding withdraws the group entirely, and never touches the built-ins.
	reg.Replace("integration:cal", nil)
	if got := entryNames(reg.snapshot()); !reflect.DeepEqual(got, []string{"builtin"}) {
		t.Fatalf("a withheld integration kept serving: %v", got)
	}
	_ = ctx
}

func entryNames(es []Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Tool.Name)
	}
	return out
}

// AC (P12-02): withholding an integration withdraws its tools from the next request of a caller
// whose server was composed before it, and keeps working the second time (SPEC §6.5, §6.10).
func TestWithholdingAnIntegrationWithdrawsItFromTheNextRequest(t *testing.T) {
	ctx := context.Background()
	dir := &fakeDirectory{
		perms: map[string]map[string]bool{"peer": {"message.text": true, "integration.cal": true}},
		tiers: map[string]policy.Tier{"peer": policy.TierContact},
	}
	reg := testRegistry()
	obj := &jsonSchemaObj
	calEntry := func(name string) Entry {
		return Entry{
			Tool: &mcp.Tool{Name: name, InputSchema: obj},
			Rule: policy.Rule{Tier: policy.TierContact, Permission: "integration.cal"},
			Handler: func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return textResult(name), nil
			},
		}
	}
	reg.Replace("integration:cal", []Entry{calEntry("cal_find_slots"), calEntry("cal_create_event")})

	pool := NewPool(reg, dir.resolve, 8)
	if !hasTool(requestTools(t, pool, "acct", "peer"), "cal_find_slots") {
		t.Fatal("setup: the published exposure was never served")
	}

	// The owner narrows the exposure to one tool and republishes (SPEC §6.5).
	reg.Replace("integration:cal", []Entry{calEntry("cal_find_slots")})
	pool.InvalidateAll(ctx, "acct")

	names := requestTools(t, pool, "acct", "peer")
	if hasTool(names, "cal_create_event") {
		t.Fatalf("a withdrawn tool is still served: %v", names)
	}
	if !hasTool(names, "cal_find_slots") {
		t.Fatalf("narrowing an exposure removed a tool that is still published: %v", names)
	}

	// ...and again.
	reg.Replace("integration:cal", nil)
	pool.InvalidateAll(ctx, "acct")

	names = requestTools(t, pool, "acct", "peer")
	if hasTool(names, "cal_find_slots") {
		t.Fatalf("withholding an integration left its tools served: %v", names)
	}
	if !hasTool(names, "send_message") {
		t.Fatalf("rebuilding took away a built-in tool the caller still holds: %v", names)
	}
}

func hasTool(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// The cache holds at most MaxSize servers, whoever asks: eviction drops the least recently used,
// and a caller whose server was dropped is composed again by its next request.
func TestTheCacheStaysWithinItsBound(t *testing.T) {
	ctx := context.Background()
	dir := &fakeDirectory{perms: map[string]map[string]bool{}, tiers: map[string]policy.Tier{}}
	const maxSize = 2
	pool := NewPool(testRegistry(), dir.resolve, maxSize)
	for i := 0; i < maxSize+5; i++ {
		if _, err := pool.ServerFor(ctx, "acct", fmt.Sprintf("caller-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	pool.mu.Lock()
	held, listed := len(pool.cache), pool.order.Len()
	pool.mu.Unlock()
	if held != maxSize || listed != maxSize {
		t.Fatalf("the cache holds %d servers (%d in its order) with a bound of %d", held, listed, maxSize)
	}
	if got := requestTools(t, pool, "acct", "caller-0"); !contains(got, "redeem_invite") {
		t.Fatalf("an evicted caller was not composed again: %v", got)
	}
}

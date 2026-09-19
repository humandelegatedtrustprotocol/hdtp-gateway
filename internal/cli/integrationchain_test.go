package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	"github.com/tech-sumit/pact-gateway/internal/outbound"
	"github.com/tech-sumit/pact-gateway/internal/public"
)

// AC (P10-04a): the chain is wired, so the machinery P3 built actually runs.
//
// `serve` used to build integrations.Manager{Store: st} — one of thirteen fields
// — and the portal separately constructed its OWN Cataloger and Exposures with
// every hook nil. This asserts the connections exist rather than that any one of
// them fires, because the defect was structural: nothing was attached to
// anything.
func TestIntegrationChainIsWired(t *testing.T) {
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	var audited []string
	changed := 0
	chain := buildIntegrationChain(st, nil, nil, "",
		func(a, r, o string) { audited = append(audited, a+" "+o) },
		func(string) { changed++ }, nil, nil)

	if chain.Manager.Audit == nil {
		t.Error("Manager.Audit is nil — every audit call inside the manager is a no-op")
	}
	if chain.Manager.HTTPClient == nil || chain.Manager.HTTPClient.Timeout == 0 {
		t.Error("upstream calls have no timeout — one dead upstream pins a goroutine")
	}
	for name, hook := range map[string]func(string){
		"OnConnected":       chain.Manager.OnConnected,
		"OnHealthy":         chain.Manager.OnHealthy,
		"OnToolListChanged": chain.Manager.OnToolListChanged,
		"OnMinted":          chain.Cataloger.OnMinted,
		"OnChange":          chain.Exposures.OnChange,
	} {
		if hook == nil {
			t.Errorf("%s is nil — the surface it feeds never updates", name)
		}
	}
	if chain.Manager.OnAvailability == nil {
		t.Error("OnAvailability is nil — a withheld integration keeps its tools listed (§6.10)")
	}
	if chain.Cataloger.Manager != chain.Manager {
		t.Error("the cataloger snapshots a different manager than the node runs")
	}

	// A withhold must reach the serving surface and be audited (§6.10).
	chain.Manager.OnAvailability("i-1", true)
	if changed != 1 {
		t.Errorf("a withheld integration did not rebuild the served surface (%d)", changed)
	}
	var sawWithheld bool
	for _, a := range audited {
		if a == "integration_availability withheld" {
			sawWithheld = true
		}
	}
	if !sawWithheld {
		t.Errorf("the withhold was not audited: %v", audited)
	}

	// The stale guard is reachable from a minted snapshot and is a no-op when
	// nothing is exposed — it must not error on a bare integration.
	acct, err := st.CreateAccount(context.Background(), store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256",
	})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(context.Background(), store.Integration{
		AccountID: acct.ID, Slug: "cal", Transport: "streamable-http",
		Endpoint: "https://x.invalid", AuthKind: "none", Status: "disabled",
	})
	if err != nil {
		t.Fatal(err)
	}
	chain.Cataloger.OnMinted(in.ID)
}

// AC (P10-04b): get_status answers from the node's own state by default.
//
// SPEC §6.7: the status provider "serves get_status from the owner's node-local
// status by default; a recipe MAY source it from an upstream tool instead". The
// Status map was never populated, so every node answered `unavailable` to
// PACT's simplest capability, forever.
func TestGetStatusAnswersWithoutAnyIntegration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")
	startServeAt(t, dir, cfgPath, internal, public)

	kp, cert := peerIdentity(t, "bob")
	st := openStoreAt(t, dir)
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: kp.Fingerprint, SPKI: mustSPKI(t, kp),
		Leaf: kp.Host.LeafDER, Endpoint: kp.Endpoint,
		Status: "active", Permissions: []string{"status.view", "calendar.availability"}, Preset: "custom",
	}); err != nil {
		t.Fatal(err)
	}
	peer, dial := nodePeer(t, dir, acct, public)
	client := &outbound.Client{Keypair: kp.KP, Cert: cert, Roots: x509.NewCertPool(), DialContext: dial}
	res, err := client.CallTool(ctx, peer, "get_status", map[string]any{}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatalf("get_status: %v", err)
	}
	body := textOf(res)
	if res.IsError {
		t.Fatalf("a node with no integration could not answer get_status: %s", body)
	}
	if !strings.Contains(body, "available") {
		t.Fatalf("node-local status was not the default: %s", body)
	}

	// The calendar has no provider, and must still answer `unavailable` (§6.10).
	// This matters because P10-04b made ToolDeps.Calendar non-nil on every node,
	// so the tool's own `== nil` short-circuit is no longer reachable in the
	// shipped binary — the resolver is what has to produce the refusal now, and
	// the unit test covering the nil branch no longer proves anything about it.
	res2, err := client.CallTool(ctx, peer, "check_availability", map[string]any{
		"window":       map[string]any{"from": "2026-09-01T09:00:00Z", "to": "2026-09-01T17:00:00Z"},
		"duration_min": 30,
	}, outbound.CallOptions{Plaintext: true})
	if err != nil {
		t.Fatalf("check_availability: %v", err)
	}
	if !res2.IsError || !strings.Contains(textOf(res2), "unavailable") {
		t.Fatalf("a node with no calendar did not answer unavailable: %s", textOf(res2))
	}
}

// AC (P10-04d): a published exposure becomes a tool a permitted contact can
// list, gated by `integration.<slug>` — and a contact without that permission
// cannot see it (SPEC §6.5, §6.6).
//
// Exposures.ActiveEntries had no caller and Passthrough appeared zero times
// outside tests, so the picker wrote a row and no contact ever gained a tool.
func TestPublishedExposureBecomesAPermittedTool(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")

	// An integration with a snapshot and a published exposure, before boot —
	// so this also proves the surface is rebuilt at startup, not only on edit.
	st0 := migrated(t, dir)
	in, err := st0.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "cal", Transport: "streamable-http",
		Endpoint: "https://upstream.invalid", AuthKind: "none", Status: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	tools := `[{"name":"find_slots","description":"find times","input_schema":{"type":"object"},"hash":"h1"}]`
	if _, err := st0.InsertCatalog(ctx, store.Catalog{IntegrationID: in.ID, Version: 1, Tools: tools}); err != nil {
		t.Fatal(err)
	}
	entries := `[{"tool":"find_slots","mode":"passthrough","exposed_name":"cal_find_slots","confirmed_hash":"h1"}]`
	if _, err := st0.InsertExposure(ctx, store.Exposure{
		IntegrationID: in.ID, Version: 1, CatalogVersion: 1, Entries: entries,
	}); err != nil {
		t.Fatal(err)
	}
	st0.Close()

	// Two contacts: one granted the per-integration permission, one not.
	granted, grantedCert := peerIdentity(t, "bob")
	plain, plainCert := peerIdentity(t, "carol")
	st1 := migrated(t, dir)
	for _, c := range []struct {
		kp    *testPeer
		perms []string
	}{
		{granted, []string{"message.text", "integration.cal"}},
		{plain, []string{"message.text"}},
	} {
		if _, err := st1.InsertContact(ctx, store.Contact{
			AccountID: acct.ID, Fingerprint: c.kp.Fingerprint, SPKI: mustSPKI(t, c.kp),
			Leaf: c.kp.Host.LeafDER, Endpoint: c.kp.Endpoint,
			Status: "active", Permissions: c.perms, Preset: "custom",
		}); err != nil {
			t.Fatal(err)
		}
	}
	st1.Close()

	startServeAt(t, dir, cfgPath, internal, public)
	peer, dial := nodePeer(t, dir, acct, public)

	// The surface is rebuilt at BOOT, not only on an edit: a node that restarts
	// must serve what it served before.
	gc := &outbound.Client{Keypair: granted.KP, Cert: grantedCert, Roots: x509.NewCertPool(), DialContext: dial}
	if !listHasTool(t, ctx, gc, peer, "cal_find_slots") {
		t.Fatal("a published exposure did not become a tool for a permitted contact")
	}

	// Nothing an upstream offers is exposed by default, and the gate is the
	// per-integration permission `integration.<slug>` (§6, §6.6).
	pc := &outbound.Client{Keypair: plain.KP, Cert: plainCert, Roots: x509.NewCertPool(), DialContext: dial}
	if listHasTool(t, ctx, pc, peer, "cal_find_slots") {
		t.Fatal("a contact without integration.cal could see the exposed tool")
	}
}

func listHasTool(t *testing.T, ctx context.Context, c *outbound.Client, peer outbound.Peer, name string) bool {
	t.Helper()
	hc, err := c.HTTPClient(peer)
	if err != nil {
		return false
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "peer", Version: "1"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: peer.Endpoint, HTTPClient: hc}, nil)
	if err != nil {
		return false
	}
	defer cs.Close()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		return false
	}
	for _, tl := range list.Tools {
		if tl.Name == name {
			return true
		}
	}
	return false
}

// AC (P10-04f): an agent-answered exposure parks a real request naming the
// caller, so the owner's agent can judge it (SPEC §6.8).
//
// AgentAnswered.Handler had no production caller, so nothing could ever create a
// pending request — and `answer_request` on the owner MCP could answer requests
// that could not exist.
func TestAgentAnsweredExposureParksARequest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	chain := buildIntegrationChain(st, nil, nil, "", func(string, string, string) {}, nil, nil, nil)
	agent := &integrations.AgentAnswered{
		Store: st, Bus: messaging.NewBus(),
		WaitBudget: 50 * time.Millisecond, TTL: time.Hour,
	}
	surf := &integrationSurface{
		store: st, chain: chain, auditFn: func(string, string, string) {}, agent: agent,
		pass: &integrations.Passthrough{Manager: chain.Manager},
	}

	acct, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "desk", Transport: "streamable-http",
		Endpoint: "https://x.invalid", AuthKind: "none", Status: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	en := integrations.ExposureEntry{Tool: "ask", Mode: integrations.ModeAgent, ExposedName: "desk_ask"}
	h, ok := surf.agentHandler(in, en, integrations.ToolDef{Name: "ask"})
	if !ok {
		t.Fatal("agent-answered mode produced no handler")
	}

	// With no identifiable caller there is nobody to route an answer back to.
	if res, _ := h(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "desk_ask"}}); !res.IsError {
		t.Fatal("a call with no caller identity was parked anyway")
	}

	cctx := public.WithCaller(ctx, policy.Caller{
		AccountID: acct.ID, Fingerprint: "sha256:contact", Tier: policy.TierContact,
	})
	// The wait budget expires with no agent answering; what matters is that the
	// request was PARKED and carries the caller.
	_, _ = h(cctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
		Name: "desk_ask", Arguments: []byte(`{"q":"when are you free"}`)}})

	rows, err := st.ListOpenPendingRequests(ctx, acct.ID, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("parked %d requests, want 1", len(rows))
	}
	if rows[0].ContactFpr != "sha256:contact" || rows[0].Capability != "desk_ask" {
		t.Fatalf("the parked request does not name who asked what: %+v", rows[0])
	}
	// The caller has no contact row, so the parked request fails SAFE to the
	// lowest grant — never an empty label (SPEC 7.6: every payload carries it).
	if rows[0].TrustFlag != "messages_only" {
		t.Fatalf("no contact row must park at messages_only, got %q", rows[0].TrustFlag)
	}

	// A caller the owner marked may_instruct parks under that label.
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: "sha256:trusted", SPKI: []byte{7}, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateContactTrust(ctx, acct.ID, "sha256:trusted", "may_instruct"); err != nil {
		t.Fatal(err)
	}
	tctx := public.WithCaller(ctx, policy.Caller{
		AccountID: acct.ID, Fingerprint: "sha256:trusted", Tier: policy.TierContact,
	})
	_, _ = h(tctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
		Name: "desk_ask", Arguments: []byte(`{"q":"and now?"}`)}})
	rows, err = st.ListOpenPendingRequests(ctx, acct.ID, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	var trusted *store.PendingRequest
	for i := range rows {
		if rows[i].ContactFpr == "sha256:trusted" {
			trusted = &rows[i]
		}
	}
	if trusted == nil || trusted.TrustFlag != "may_instruct" {
		t.Fatalf("the owner's grant did not reach the parked row: %+v", rows)
	}
}

// AC (P10-04a/c/d + P10-08h, end to end): an exposure change made through the
// owner MCP reaches what a CONTACT can list, on a running node.
//
// This is the chain P10 assembled, proven in one pass: owner-MCP set_exposure →
// Exposures.Publish → OnChange → the surface rebuild → Registry.Replace →
// Pool.InvalidateAll → the caller's tools/list. Each link was tested; nothing
// exercised them together, and every hollow-done in this project lived exactly
// in an untested join.
func TestExposureChangeThroughOwnerMCPReachesAContact(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	internal, public := freePort(t), freePort(t)
	b, _ := json.Marshal(map[string]any{
		"data_dir": dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "seal": "optional", "client_cert": "preferred",
	})
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	acct := seedAccount(t, dir, "alice")

	st0 := migrated(t, dir)
	in, err := st0.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "cal", Transport: "streamable-http",
		Endpoint: "https://upstream.invalid", AuthKind: "none", Status: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st0.InsertCatalog(ctx, store.Catalog{
		IntegrationID: in.ID, Version: 1,
		Tools: `[{"name":"find_slots","description":"find","input_schema":{"type":"object"},"hash":"h1"},` +
			`{"name":"book","description":"book","input_schema":{"type":"object"},"hash":"h2"}]`,
	}); err != nil {
		t.Fatal(err)
	}
	// Nothing published yet: the contact starts with no integration tools.
	kp, cert := peerIdentity(t, "bob")
	if _, err := st0.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: kp.Fingerprint, SPKI: mustSPKI(t, kp),
		Leaf: kp.Host.LeafDER, Endpoint: kp.Endpoint,
		Status: "active", Permissions: []string{"message.text", "integration.cal"}, Preset: "custom",
	}); err != nil {
		t.Fatal(err)
	}
	// A token belongs to an owner, so one must exist before the portal will
	// mint one (SPEC §3, §8.6).
	o, err := st0.CreateOwnerWithID(ctx, "", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := st0.AddMembership(ctx, o.ID, acct.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	st0.Close()

	r := startServeAt(t, dir, cfgPath, internal, public)
	peer, dial := nodePeer(t, dir, acct, public)
	client := &outbound.Client{Keypair: kp.KP, Cert: cert, Roots: x509.NewCertPool(), DialContext: dial}

	if listHasTool(t, ctx, client, peer, "cal_find_slots") {
		t.Fatal("a tool was served before anything was published")
	}

	// The owner's agent publishes one tool, over the real owner-MCP surface.
	tok := mintOwnerToken(t, dir, r)
	callOwnerMCP(t, r, tok, "set_exposure", map[string]any{
		"account_id": acct.ID, "integration_id": in.ID, "tools": []string{"find_slots"},
	})
	waitFor(t, 20*time.Second, "publishing through the owner MCP never reached the contact", func() bool {
		return listHasTool(t, ctx, client, peer, "cal_find_slots")
	})
	if listHasTool(t, ctx, client, peer, "cal_book") {
		t.Fatal("a tool the owner did not publish was served")
	}

	// Narrowing to nothing must WITHDRAW it — the case a registry that could
	// only grow got wrong, and the one an owner reaches for in a hurry.
	callOwnerMCP(t, r, tok, "set_exposure", map[string]any{
		"account_id": acct.ID, "integration_id": in.ID, "tools": []string{},
	})
	waitFor(t, 20*time.Second, "withdrawing an exposure did not stop it being served", func() bool {
		return !listHasTool(t, ctx, client, peer, "cal_find_slots")
	})
}

// mintOwnerToken creates an owner-MCP bearer token through the portal, the way
// an owner does.
func mintOwnerToken(t *testing.T, dir string, r *running) string {
	t.Helper()
	p := newPortal(t, "http://"+r.internal)
	body := p.post("/owners/tokens/create", url.Values{"label": {"test agent"}})
	var minted struct {
		NewToken string `json:"new_token"`
	}
	if err := json.Unmarshal([]byte(body), &minted); err != nil || !strings.HasPrefix(minted.NewToken, "pact_") {
		t.Fatalf("no token in the response: %v %s", err, firstLine(body))
	}
	return minted.NewToken
}

// callOwnerMCP invokes one owner-MCP tool over the real HTTP surface.
func callOwnerMCP(t *testing.T, r *running, token, tool string, args map[string]any) {
	t.Helper()
	ctx := context.Background()
	cs, err := dialOwnerMCP(ctx, "http://"+r.internal+"/owner/mcp", "Bearer "+token)
	if err != nil {
		t.Fatalf("owner MCP dial: %v", err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		t.Fatalf("%s refused: %s", tool, textOf(res))
	}
}

// AC (P12-11, tightened by P13-02): the agent-answered service must know about
// owner presence from the moment it EXISTS, not from the moment the owner-MCP
// handler is built.
//
// SPEC §6.8 point 4: the fallback chain runs when the wait budget expires "or no
// agent session is connected", and a nil Connected reads as "assume connected".
// P12-11 set it inside ownerMCPHandler — which `serve` does not build until
// after nd.Start has opened the PUBLIC listener and the stored integrations have
// been reconnected, and reconnecting is what republishes agent-answered
// exposures. For the whole of boot the field was nil again, so a contact calling
// an agent-answered capability was held for the full 30 s budget: the defect
// P12-11 fixed, through the startup window it left behind.
//
// Pairing the two in one constructor is what makes the window unreachable, so
// that is what this pins — not a line ordering somebody can quietly move.
func TestAgentAnsweredKnowsAboutPresenceFromConstruction(t *testing.T) {
	agent, presence := newAgentAnswered(nil, nil)
	if agent == nil || presence == nil {
		t.Fatal("the constructor returned a nil half")
	}
	if agent.Connected == nil {
		t.Fatal("AgentAnswered was born with Connected nil, so during boot the node " +
			"assumes an owner agent is listening when none is")
	}
	if agent.Connected("any-account") {
		t.Fatal("reported an owner agent connected when no owner session exists")
	}
	// The returned tracker is the one the agent consults — not a copy.
	srv := mcp.NewServer(&mcp.Implementation{Name: "owner", Version: "1"}, nil)
	presence.add(srv)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "a", Version: "1"}, nil).
		Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cs.Close(); ss.Wait() }()
	if !agent.Connected("any-account") {
		t.Fatal("a session on the returned tracker did not reach the agent")
	}
}

// ownerPresence prunes servers that no longer hold a session, so a reconnecting
// agent does not accumulate entries and a departed one stops counting.
func TestOwnerPresenceTracksLiveSessionsOnly(t *testing.T) {
	p := &ownerPresence{}
	if p.any() {
		t.Fatal("an empty tracker reported a live agent")
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "owner", Version: "1"}, nil)
	p.add(srv)
	if p.any() {
		t.Fatal("a server with no sessions reported a live agent")
	}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "a", Version: "1"}, nil).
		Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.any() {
		t.Fatal("a connected owner session was not seen")
	}
	cs.Close()
	ss.Wait()
	if p.any() {
		t.Fatal("a closed owner session still counted as a live agent")
	}
	if len(p.entries) != 0 {
		t.Fatalf("%d dead servers retained; the tracker grows per reconnect", len(p.entries))
	}
}

package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/public"
)

type recAudit struct {
	mu   sync.Mutex
	rows []string
}

func (a *recAudit) fn(action, resource, outcome string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, action+" "+resource+" "+outcome)
}

// hasRow matches a row by its three parts independently. The account a row is
// attributed to sits between the action and the resource, so an assertion that
// expects them adjacent is asserting the row is unattributed.
func (a *recAudit) hasRow(action, resource, outcome string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.rows {
		if strings.HasPrefix(r, action+" ") && strings.Contains(r, " "+resource+" ") &&
			strings.HasSuffix(r, " "+outcome) {
			return true
		}
	}
	return false
}

func (a *recAudit) has(sub string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.rows {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func manageEnv(t *testing.T) (*http.ServeMux, *store.SQLite, *recAudit, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "mg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Sumit", Algo: "p256"})
	_ = st.SetAccountKey(ctx, a.ID, "sha256:mykey", []byte{9})
	aud := &recAudit{}
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{
		Store: st, Contacts: &contacts.Manager{Store: st}, Audit: aud.fn,
		PublicURL: func() string { return "https://pact.example" },
		SignCard:  func(_, _ string) (string, error) { return "c2ln", nil },
	})
	return mux, st, aud, a.ID
}

func postForm(t *testing.T, mux *http.ServeMux, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestApproveAndRejectFlows(t *testing.T) {
	mux, st, aud, acct := manageEnv(t)
	ctx := context.Background()
	for _, fpr := range []string{"sha256:ask1", "sha256:ask2"} {
		_, _ = st.InsertContact(ctx, store.Contact{AccountID: acct, Fingerprint: fpr, Status: "pending_in", SPKI: []byte{1}})
	}

	// requests page lists both
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/requests?account="+acct, nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "sha256:ask1") {
		t.Fatalf("requests: %d %s", rr.Code, rr.Body.String())
	}

	// approve with preset
	if rr := postForm(t, mux, "/requests/sha256:ask1/approve?account="+acct, url.Values{"preset": {"friend"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d", rr.Code)
	}
	c, _ := st.GetContact(ctx, acct, "sha256:ask1")
	if c.Status != "active" || c.Preset != "friend" || len(c.Permissions) != len(contacts.DefaultPresets["friend"]) {
		t.Fatalf("approved contact: %+v", c)
	}
	// reject → silent demotion to blocked
	if rr := postForm(t, mux, "/requests/sha256:ask2/reject?account="+acct, url.Values{}); rr.Code != http.StatusSeeOther {
		t.Fatalf("reject: %d", rr.Code)
	}
	c2, _ := st.GetContact(ctx, acct, "sha256:ask2")
	if c2.Status != "blocked" {
		t.Fatalf("rejected contact: %+v", c2)
	}
	// approving a non-pending contact fails + audits error
	if rr := postForm(t, mux, "/requests/sha256:ask1/approve?account="+acct, url.Values{}); rr.Code != http.StatusNotFound {
		t.Fatalf("re-approve: %d", rr.Code)
	}
	// Attributed to the account, so the row is scoped to the owner who
	// administers it rather than readable by every owner on the node.
	for _, want := range []string{
		"contact_approve account:" + acct + " contact:sha256:ask1 ok",
		"contact_reject account:" + acct + " contact:sha256:ask2 ok",
		"contact_approve account:" + acct + " contact:sha256:ask1 error",
	} {
		if !aud.has(want) {
			t.Fatalf("missing %q in audit rows: %v", want, aud.rows)
		}
	}
}

func TestInviteLifecyclePages(t *testing.T) {
	mux, st, aud, acct := manageEnv(t)
	ctx := context.Background()

	rr := postForm(t, mux, "/invites/create?account="+acct, url.Values{
		"label": {"party"}, "max_uses": {"5"}, "auto_accept": {"1"}, "preset": {"basic"},
	})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create: %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "&new=") {
		t.Fatalf("token not carried once: %s", loc)
	}
	// list shows the row
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/invites?account="+acct, nil))
	if !strings.Contains(rr2.Body.String(), `"Label":"party"`) || !strings.Contains(rr2.Body.String(), `"MaxUses":5`) {
		t.Fatalf("invites payload: %s", rr2.Body.String())
	}
	invs, _ := st.ListInvites(ctx, acct)
	if len(invs) != 1 || !invs[0].AutoAccept {
		t.Fatalf("invite row: %+v", invs)
	}
	// revoke
	if rr := postForm(t, mux, "/invites/"+invs[0].ID+"/revoke?account="+acct, url.Values{}); rr.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rr.Code)
	}
	invs, _ = st.ListInvites(ctx, acct)
	if invs[0].RevokedAt == 0 {
		t.Fatal("not revoked")
	}
	if !aud.has("invite_create") || !aud.has("invite_revoke") {
		t.Fatalf("audit rows: %v", aud.rows)
	}
}

func TestCardPageAndVCFDownloadRoundTrip(t *testing.T) {
	mux, _, _, acct := manageEnv(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/card.vcf?account="+acct, nil))
	if rr.Code != 200 {
		t.Fatalf("vcf: %d", rr.Code)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="me.vcf"`) {
		t.Fatalf("disposition: %s", cd)
	}
	// the download IS a P1-12 card: parse and verify fields
	c, err := contacts.ParseCard(rr.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	if c.FN != "Sumit" || c.Key != "sha256:mykey" || c.Endpoint != "https://pact.example/a/me/mcp" || c.Version == "" {
		t.Fatalf("card fields: %+v", c)
	}
	// The API hands the SPA the same card + its signature
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/card?account="+acct, nil))
	if !strings.Contains(rr2.Body.String(), "X-PACT-KEY:sha256:mykey") || !strings.Contains(rr2.Body.String(), "c2ln") {
		t.Fatalf("card payload: %s", rr2.Body.String())
	}
}

// A request is approved in the portal, and the requester's NEXT call must see
// the contact surface. The pool composes a server per caller and caches it; the
// requester called before approval (that is how the request came to exist), so
// a cached GUEST surface is sitting there. The owner MCP's approve reconciled
// it; the portal's did not, and every message the new contact sent came back
// permission_denied while the owner's own page showed the permission granted.
func TestPortalApprovalReachesTheCallersLiveSurface(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	const asker = "sha256:asker"
	if _, err := st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: asker, Status: "pending_in", SPKI: []byte{1}}); err != nil {
		t.Fatal(err)
	}

	reg := &public.Registry{}
	obj := &schemaObj
	nop := func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	}
	reg.Add(
		public.Entry{Tool: &mcp.Tool{Name: "request_contact", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierGuest}, Handler: nop},
		public.Entry{Tool: &mcp.Tool{Name: "send_message", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierContact, Permission: "message.text"}, Handler: nop},
	)
	pool := public.NewPool(reg, public.StoreResolver(st), 8)

	tools := func() []string {
		t.Helper()
		srv, err := pool.ServerFor(ctx, a.ID, asker)
		if err != nil {
			t.Fatal(err)
		}
		ct, stt := mcp.NewInMemoryTransports()
		ss, err := srv.Connect(ctx, stt, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ss.Wait()
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		res, _ := cs.ListTools(ctx, nil)
		var names []string
		for _, x := range res.Tools {
			names = append(names, x.Name)
		}
		return names
	}
	// The requester called before approval, so their guest surface is cached.
	if got := tools(); len(got) != 1 || got[0] != "request_contact" {
		t.Fatalf("precondition: guest surface expected, got %v", got)
	}

	aud := &recAudit{}
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{
		Store: st, Contacts: &contacts.Manager{Store: st}, Audit: aud.fn, Invalidate: pool.Invalidate,
		PublicURL: func() string { return "https://pact.example" },
	})
	rr := postForm(t, mux, "/requests/"+asker+"/approve?account="+a.ID, url.Values{"preset": {"basic"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}

	got := tools()
	has := false
	for _, n := range got {
		if n == "send_message" {
			has = true
		}
	}
	if !has {
		t.Fatalf("after a portal approval the caller still sees %v — the cached guest surface was never invalidated, so their next message is refused", got)
	}
}

// A pending request that came through an invite shows which one — the owner's
// own context, more trustworthy than the caller's claimed name. A cold request
// shows nothing.
func TestRequestsShowTheAdmittingInvite(t *testing.T) {
	mux, st, _, acct := manageEnv(t)
	ctx := context.Background()
	inv, err := st.InsertInvite(ctx, store.Invite{
		AccountID: acct, TokenHash: []byte{9, 9}, ExpiresAt: 4102444800, MaxUses: 5, Label: "Pune conference 2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct, Fingerprint: "sha256:via", Status: "pending_in", DisplayName: "V", InviteID: inv.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct, Fingerprint: "sha256:cold", Status: "pending_in", DisplayName: "C",
	}); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/requests?account="+acct, nil))
	body := rr.Body.String()
	if !strings.Contains(body, `"via_invite":true`) || !strings.Contains(body, "Pune conference 2026") {
		t.Fatalf("invite context missing: %s", body)
	}
	var out struct {
		Pending []struct {
			Fingerprint string `json:"fingerprint"`
			ViaInvite   bool   `json:"via_invite"`
			InviteLabel string `json:"invite_label"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range out.Pending {
		if p.Fingerprint == "sha256:cold" && (p.ViaInvite || p.InviteLabel != "") {
			t.Fatalf("a cold request claims an invite: %+v", p)
		}
	}
}

// An owner-edited bundle drives approval end to end: the grant is the custom
// bundle, the label survives while it holds, and the compiled-in defaults are
// no longer offered once rows exist.
func TestApproveWithAnOwnerEditedPreset(t *testing.T) {
	mux, st, _, acct := manageEnv(t)
	ctx := context.Background()
	if err := st.PutSetting(ctx, store.Setting{
		Key: "preset.close", Value: "message.text,message.media", UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: acct, Fingerprint: "sha256:ask-close", Status: "pending_in", DisplayName: "C",
	}); err != nil {
		t.Fatal(err)
	}
	rr := postForm(t, mux, "/requests/sha256:ask-close/approve?account="+acct, url.Values{"preset": {"close"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d", rr.Code)
	}
	c, _ := st.GetContact(ctx, acct, "sha256:ask-close")
	if c.Preset != "close" || len(c.Permissions) != 2 {
		t.Fatalf("custom bundle not applied: %+v", c)
	}
	// The offered list is the owner's set now — "basic" is gone.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/requests?account="+acct, nil))
	if body := rr.Body.String(); !strings.Contains(body, `"close"`) || strings.Contains(body, `"basic"`) {
		t.Fatalf("offered presets: %s", body)
	}
}

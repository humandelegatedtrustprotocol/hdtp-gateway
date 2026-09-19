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

type auditRec struct {
	mu   sync.Mutex
	rows []string
}

func (a *auditRec) fn(action, resource, outcome string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rows = append(a.rows, action+" "+resource+" "+outcome)
}

func switchboardEnv(t *testing.T) (*http.ServeMux, *store.SQLite, *public.Pool, *auditRec, string) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "sb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if _, err := st.InsertContact(ctx, store.Contact{
		AccountID: a.ID, Fingerprint: "sha256:alina", SPKI: []byte{1}, Status: "active",
		Permissions: []string{"message.text", "calendar.book"}, DisplayName: "Alina",
	}); err != nil {
		t.Fatal(err)
	}

	reg := &public.Registry{}
	obj := &schemaObj
	echo := func(name string) mcp.ToolHandler {
		return func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: name}}}, nil
		}
	}
	reg.Add(
		public.Entry{Tool: &mcp.Tool{Name: "send_message", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierContact, Permission: "message.text"}, Handler: echo("send_message")},
		public.Entry{Tool: &mcp.Tool{Name: "book_slot", InputSchema: obj}, Rule: policy.Rule{Tier: policy.TierContact, Permission: "calendar.book"}, Handler: echo("book_slot")},
	)
	pool := public.NewPool(reg, public.StoreResolver(st), 8)

	aud := &auditRec{}
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{Store: st, Invalidate: pool.Invalidate, Audit: aud.fn})
	return mux, st, pool, aud, a.ID
}

func TestToggleFlipPersistsAuditsAndNotifiesLiveSession(t *testing.T) {
	mux, st, pool, aud, acct := switchboardEnv(t)
	ctx := context.Background()

	// live MCP session for alina
	srv, err := pool.ServerFor(ctx, acct, "sha256:alina")
	if err != nil {
		t.Fatal(err)
	}
	ct, stt := mcp.NewInMemoryTransports()
	srvSession, err := srv.Connect(ctx, stt, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srvSession.Wait()
	changed := make(chan struct{}, 2)
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	})
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, _ := cs.ListTools(ctx, nil)
	if len(res.Tools) != 2 {
		t.Fatalf("precondition: %d tools", len(res.Tools))
	}

	// flip the switchboard: revoke calendar.book via form POST
	form := url.Values{"perm": {"message.text"}, "preset": {"basic"}}
	req := httptest.NewRequest("POST", "/contacts/sha256:alina/permissions?account="+acct, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("toggle POST: %d", rr.Code)
	}

	// persisted
	c, _ := st.GetContact(ctx, acct, "sha256:alina")
	// The resulting grant happens to equal the basic bundle. That is a
	// coincidence, not a choice: a preset is only ever applied, never inferred.
	if len(c.Permissions) != 1 || c.Permissions[0] != "message.text" || c.Preset != "" {
		t.Fatalf("not persisted: %+v", c)
	}
	// audited
	aud.mu.Lock()
	rows := append([]string(nil), aud.rows...)
	aud.mu.Unlock()
	// The resource carries the resulting grant set and the label it now wears:
	// an outcome alone cannot say what a switchboard change did, which is the
	// question it raises. The outcome stays a verdict — the portal colours,
	// counts and filters by it, so anything else in that column turns one row
	// into its own category.
	// It is also attributed: the account column is what scopes a narrowed
	// token's reads and the portal's own audit page, and an unattributed row
	// is readable by every owner on the node.
	if len(rows) != 1 ||
		!strings.Contains(rows[0], "account:"+acct) ||
		!strings.Contains(rows[0], "contact:sha256:alina perms:message.text preset:custom") ||
		!strings.HasSuffix(rows[0], " ok") {
		t.Fatalf("audit rows: %v", rows)
	}
	// live session notified and sees the narrowed surface
	<-changed
	res2, _ := cs.ListTools(ctx, nil)
	if len(res2.Tools) != 1 || res2.Tools[0].Name != "send_message" {
		t.Fatalf("live session still sees: %+v", res2.Tools)
	}
}

func TestPresetApplySetsDocumentedBundle(t *testing.T) {
	mux, st, _, _, acct := switchboardEnv(t)
	form := url.Values{"preset": {"friend"}, "apply_preset": {"1"}}
	req := httptest.NewRequest("POST", "/contacts/sha256:alina/permissions?account="+acct, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("preset POST: %d", rr.Code)
	}
	c, _ := st.GetContact(context.Background(), acct, "sha256:alina")
	if len(c.Permissions) != len(contacts.DefaultPresets["friend"]) || c.Preset != "friend" {
		t.Fatalf("bundle not applied: %+v", c)
	}
}

func TestTrustFlagUpdate(t *testing.T) {
	mux, st, _, aud, acct := switchboardEnv(t)
	form := url.Values{"trust": {"may_instruct"}}
	req := httptest.NewRequest("POST", "/contacts/sha256:alina/trust?account="+acct, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("trust POST: %d", rr.Code)
	}
	c, _ := st.GetContact(context.Background(), acct, "sha256:alina")
	if c.TrustFlag != "may_instruct" {
		t.Fatalf("trust not persisted: %+v", c)
	}
	badForm := url.Values{"trust": {"root_access"}}
	req2 := httptest.NewRequest("POST", "/contacts/sha256:alina/trust?account="+acct, strings.NewReader(badForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("bogus trust value accepted: %d", rr2.Code)
	}
	aud.mu.Lock()
	defer aud.mu.Unlock()
	if len(aud.rows) != 1 {
		t.Fatalf("audit rows: %v", aud.rows)
	}
}

// SPEC §6.4: an exposed integration tool is authorized by `integration.<slug>`.
// The switchboard offered a hard-coded five, so that permission could never be
// granted — every tool an owner exposed stayed invisible to the contact it was
// exposed for, with nothing in the UI to say why. The rows now come from what
// this account's surface actually serves, plus whatever the contact already holds.
func TestSwitchboardOffersWhatTheNodeServes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	const fpr = "sha256:peer"
	if _, err := e.st.InsertContact(ctx, store.Contact{
		AccountID: acct.ID, Fingerprint: fpr, DisplayName: "peer", Status: "active",
		Permissions: []string{"message.text"}, Preset: "basic",
	}); err != nil {
		t.Fatal(err)
	}
	var served []string
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Store:             e.st,
		Audit:             func(string, string, string) {},
		Invalidate:        func(context.Context, string, string) error { return nil },
		ServedPermissions: func(string) []string { return served },
	})
	rows := func() []string {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/contacts/"+fpr+"?account="+acct.ID, nil))
		if rr.Code != 200 {
			t.Fatalf("contact page: %d %s", rr.Code, rr.Body.String())
		}
		var page struct {
			Permissions []struct {
				Name string `json:"name"`
			} `json:"permissions"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(page.Permissions))
		for _, p := range page.Permissions {
			out = append(out, p.Name)
		}
		return out
	}
	has := func(list []string, want string) bool {
		for _, x := range list {
			if x == want {
				return true
			}
		}
		return false
	}

	if got := rows(); has(got, "integration.batondeck") {
		t.Fatalf("offered an integration nothing serves: %v", got)
	}
	// the account's surface now gates a tool with the integration's permission
	served = []string{"message.text", "integration.batondeck"}
	got := rows()
	if !has(got, "integration.batondeck") {
		t.Fatalf("a live integration cannot be granted, so its exposed tools are unreachable: %v", got)
	}
	if len(got) != len(contacts.AllPermissions)+1 {
		t.Fatalf("a core permission was duplicated: %v", got)
	}
	// A grant the surface no longer serves still shows, or the next save drops it
	// without the owner deciding to.
	served = nil
	if err := e.st.UpdateContactPermissions(ctx, acct.ID, fpr, []string{"integration.batondeck"}, ""); err != nil {
		t.Fatal(err)
	}
	if got := rows(); !has(got, "integration.batondeck") {
		t.Fatalf("a held grant vanished from the switchboard: %v", got)
	}

	// And what the switchboard offers, the save accepts: the validation used to
	// be the same hard-coded five, so granting an integration answered 200,
	// audited ok, and persisted nothing.
	served = []string{"integration.batondeck"}
	form := url.Values{"perm": {"message.text", "integration.batondeck", "not.a.permission"}}
	rr := postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID, form)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	c, err := e.st.GetContact(ctx, acct.ID, fpr)
	if err != nil {
		t.Fatal(err)
	}
	if !has(c.Permissions, "integration.batondeck") || !has(c.Permissions, "message.text") {
		t.Fatalf("the grant did not persist: %v", c.Permissions)
	}
	if has(c.Permissions, "not.a.permission") {
		t.Fatalf("a permission nothing offers was accepted: %v", c.Permissions)
	}

	// Applying a preset sets the core bundle. It must not revoke an integration
	// the owner granted deliberately: no bundle contains one, so the control
	// would be taking away a capability it never mentions.
	rr = postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID,
		url.Values{"preset": {"basic"}, "apply_preset": {"1"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rr.Code)
	}
	c, _ = e.st.GetContact(ctx, acct.ID, fpr)
	if !has(c.Permissions, "integration.batondeck") {
		t.Fatalf("applying a preset revoked an integration grant: %v", c.Permissions)
	}
	if !has(c.Permissions, "message.text") || has(c.Permissions, "calendar.book") {
		t.Fatalf("the preset was not applied to the core bundle: %v", c.Permissions)
	}
	if c.Preset != "basic" {
		t.Fatalf("an applied preset was not recorded: %q", c.Preset)
	}

	// The select rides along on every save; only an applied preset changes it.
	// This save leaves the grant equal to the basic bundle, so the label it was
	// given still describes it and survives.
	rr = postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID,
		url.Values{"preset": {"family"}, "perm": {"message.text"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rr.Code)
	}
	if c, _ = e.st.GetContact(ctx, acct.ID, fpr); c.Preset != "basic" {
		t.Fatalf("an unapplied preset rewrote the record: %q", c.Preset)
	}

	// Hand-toggling the switchboard away from the bundle clears the label. This
	// is the bug the owner reported: a record kept claiming a preset over
	// permissions that were nothing like it, and the chat panel repeated it.
	rr = postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID,
		url.Values{"perm": {"message.text", "calendar.book"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rr.Code)
	}
	if c, _ = e.st.GetContact(ctx, acct.ID, fpr); c.Preset != "" {
		t.Fatalf("a hand-tuned grant kept a preset name: %q", c.Preset)
	}
	if !has(c.Permissions, "calendar.book") {
		t.Fatalf("the hand-tuned grant was not saved: %v", c.Permissions)
	}

	// And the detail API never shows a label the grant has not earned.
	req := httptest.NewRequest("GET", "/api/contacts/"+fpr+"?account="+acct.ID, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	var shown struct {
		Preset string `json:"preset"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &shown); err != nil {
		t.Fatalf("detail api: %v (%s)", err, rr.Body.String())
	}
	if shown.Preset != "" {
		t.Fatalf("the portal showed an unearned preset: %q", shown.Preset)
	}

	// Choosing "custom" explicitly is a decision the form can express: apply it
	// and the switches posted alongside stand on their own, with no label.
	rr = postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID,
		url.Values{"preset": {""}, "apply_preset": {"1"}, "perm": {"message.text", "status.view"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("apply custom: %d", rr.Code)
	}
	if c, _ = e.st.GetContact(ctx, acct.ID, fpr); c.Preset != "" || !has(c.Permissions, "status.view") {
		t.Fatalf("custom apply: %+v", c)
	}

	// And it clears even when the switches still equal the stored bundle. The
	// first version only cleared through PresetHolds, so choosing "custom" over
	// a grant that happened to still match kept the old label — the explicit
	// decision was silently ignored.
	rr = postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID,
		url.Values{"preset": {"basic"}, "apply_preset": {"1"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("re-apply basic: %d", rr.Code)
	}
	rr = postForm(t, mux, "/contacts/"+fpr+"/permissions?account="+acct.ID,
		url.Values{"preset": {""}, "apply_preset": {"1"}, "perm": {"message.text", "integration.batondeck"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("apply custom over a matching grant: %d", rr.Code)
	}
	c, _ = e.st.GetContact(ctx, acct.ID, fpr)
	if c.Preset != "" {
		t.Fatalf("custom was ignored because the grant still matched the bundle: %q", c.Preset)
	}
	if !has(c.Permissions, "message.text") || !has(c.Permissions, "integration.batondeck") {
		t.Fatalf("custom apply dropped switches: %v", c.Permissions)
	}
}

// PACT §5: removal notifies the peer and deletes the pin — effective locally
// regardless. The remove route had no coverage at all until this.
func TestRemoveNotifiesThePeerBestEffort(t *testing.T) {
	type call struct{ fpr, tool string }
	env := func(t *testing.T, callErr error, withCall bool) (*http.ServeMux, *store.SQLite, *[]call, string) {
		t.Helper()
		st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "rm.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		ctx := context.Background()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
		var calls []call
		deps := ContactsDeps{Store: st, Audit: (&auditRec{}).fn}
		if withCall {
			deps.Call = func(_ context.Context, _, fpr, tool string, _ map[string]any) (string, error) {
				calls = append(calls, call{fpr, tool})
				return "", callErr
			}
		}
		mux := http.NewServeMux()
		MountContactPages(mux, deps)
		return mux, st, &calls, a.ID
	}
	insert := func(t *testing.T, st *store.SQLite, acct, fpr, status string) {
		t.Helper()
		if _, err := st.InsertContact(context.Background(), store.Contact{
			AccountID: acct, Fingerprint: fpr, SPKI: []byte{1}, Status: status, DisplayName: "P",
		}); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(t *testing.T, mux *http.ServeMux, acct, fpr string) *httptest.ResponseRecorder {
		t.Helper()
		return postForm(t, mux, "/contacts/"+fpr+"/remove?account="+acct, url.Values{})
	}

	t.Run("an active contact is told, then deleted", func(t *testing.T) {
		mux, st, calls, acct := env(t, nil, true)
		insert(t, st, acct, "sha256:p1", "active")
		if rr := remove(t, mux, acct, "sha256:p1"); rr.Code != http.StatusSeeOther {
			t.Fatalf("remove: %d", rr.Code)
		}
		if len(*calls) != 1 || (*calls)[0] != (call{"sha256:p1", "remove_contact"}) {
			t.Fatalf("peer calls: %+v", *calls)
		}
		if _, err := st.GetContact(context.Background(), acct, "sha256:p1"); err == nil {
			t.Fatal("row survived the remove")
		}
	})
	t.Run("an unreachable peer never blocks the delete", func(t *testing.T) {
		mux, st, _, acct := env(t, context.DeadlineExceeded, true)
		insert(t, st, acct, "sha256:p2", "active")
		rr := remove(t, mux, acct, "sha256:p2")
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("remove: %d", rr.Code)
		}
		if loc := rr.Header().Get("Location"); !strings.Contains(loc, "could+not+be+told") &&
			!strings.Contains(loc, "could%20not%20be%20told") {
			t.Fatalf("the owner was not told the peer was not: %s", loc)
		}
		if _, err := st.GetContact(context.Background(), acct, "sha256:p2"); err == nil {
			t.Fatal("row survived")
		}
	})
	t.Run("a pending contact has no relationship to notify", func(t *testing.T) {
		mux, st, calls, acct := env(t, nil, true)
		insert(t, st, acct, "sha256:p3", "pending_in")
		if rr := remove(t, mux, acct, "sha256:p3"); rr.Code != http.StatusSeeOther {
			t.Fatalf("remove: %d", rr.Code)
		}
		if len(*calls) != 0 {
			t.Fatalf("a pending contact was notified: %+v", *calls)
		}
	})
	t.Run("no Call wired means a plain delete", func(t *testing.T) {
		mux, st, _, acct := env(t, nil, false)
		insert(t, st, acct, "sha256:p4", "active")
		if rr := remove(t, mux, acct, "sha256:p4"); rr.Code != http.StatusSeeOther {
			t.Fatalf("remove: %d", rr.Code)
		}
		if _, err := st.GetContact(context.Background(), acct, "sha256:p4"); err == nil {
			t.Fatal("row survived")
		}
	})
}

// The button on a contact's page: one POST with the contact in its path, and the outcome in the
// answer — a redirect would throw away the only thing the owner pressed it to learn.
func TestRefreshRouteNamesOneContactAndAnswersWhatWasFound(t *testing.T) {
	type asked struct{ account, fpr string }
	var calls []asked
	mux := http.NewServeMux()
	MountContactPages(mux, ContactsDeps{
		Audit: (&auditRec{}).fn,
		RefreshContact: func(_ context.Context, accountID, fpr string) (string, string, error) {
			calls = append(calls, asked{accountID, fpr})
			if fpr == "sha256:gone" {
				return "", "", context.DeadlineExceeded // any error: nobody was asked
			}
			return "renewed", "", nil
		},
	})
	post := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
		return w
	}

	w := post("/contacts/sha256:alina/refresh?account=acct-1")
	var got struct{ Outcome, Why string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Outcome != "renewed" {
		t.Fatalf("the page must be told what was found: %d %s", w.Code, w.Body.String())
	}
	if w := post("/contacts/sha256:gone/refresh?account=acct-1"); w.Code != http.StatusNotFound {
		t.Fatalf("a contact that cannot be called answered %d, want 404", w.Code)
	}
	want := []asked{{"acct-1", "sha256:alina"}, {"acct-1", "sha256:gone"}}
	if len(calls) != len(want) || calls[0] != want[0] || calls[1] != want[1] {
		t.Fatalf("the node was asked for %v, want exactly %v", calls, want)
	}

	// A portal composed without a node behind it offers no refresh rather than a button that
	// answers "unchanged" about a contact nobody asked.
	bare := http.NewServeMux()
	MountContactPages(bare, ContactsDeps{Audit: (&auditRec{}).fn})
	wb := httptest.NewRecorder()
	bare.ServeHTTP(wb, httptest.NewRequest(http.MethodPost, "/contacts/sha256:alina/refresh?account=acct-1", nil))
	if wb.Code != http.StatusNotFound {
		t.Fatalf("a refresh with nothing behind it answered %d, want 404", wb.Code)
	}
}

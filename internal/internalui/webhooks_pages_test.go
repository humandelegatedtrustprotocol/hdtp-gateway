package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/webhooks"
)

// The Webhooks page's routes through the whole portal (session, CSRF, account resolution), with
// the refusals of Building rule 3: no session, no CSRF token, an endpoint that does not exist, an
// endpoint of another account (under one's own account, and with that account named), a malformed
// URL, one too long, an event the node does not send and a status that is neither. The control is the owner's
// own endpoint, which every route acts on. Nothing a refusal names is changed, and the service's
// audit rows are the only ones written.
func TestTheWebhooksPageRefusesWhatItMustAndServesTheOwnersOwn(t *testing.T) {
	ctx := context.Background()
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	var svc *webhooks.Service
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		svc = webhooks.New(st, kr, func(a, r, o string) { rows = append(rows, a+" "+r+" "+o) })
		MountWebhookPages(mux, WebhooksDeps{Webhooks: svc})
	})
	me, session := e.signIn(t, "Me")
	them, _ := e.signIn(t, "Them")
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	theirs, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"})
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, them, theirs.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	theirEndpoint, _, err := svc.Create(ctx, theirs.ID, "https://theirs.example.test/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	rows = nil

	type answer struct {
		code int
		body map[string]any
	}
	send := func(method, path string, form url.Values, signedIn, csrf bool) answer {
		t.Helper()
		var req *http.Request
		if method == http.MethodGet {
			req = httptest.NewRequest(method, path+"?"+form.Encode(), nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Host = "localhost:8080"
		req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
		if csrf {
			req.Header.Set("X-HDTP-Csrf", "tok")
		}
		if signedIn {
			req.AddCookie(session)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return answer{rec.Code, body}
	}
	as := func(account string, kv ...string) url.Values {
		v := url.Values{"account": {account}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	endpointsOf := func(account string) []webhooks.EndpointView {
		t.Helper()
		list, err := svc.List(ctx, account)
		if err != nil {
			t.Fatal(err)
		}
		return list
	}

	// No session: refused at the gate, under /api/ and for a post alike; nothing is registered.
	if a := send(http.MethodGet, "/api/webhooks", as(mine.ID), false, false); a.code != http.StatusUnauthorized {
		t.Fatalf("a read with no session: %d", a.code)
	}
	if a := send(http.MethodPost, "/webhooks/create", as(mine.ID, "url", "https://hooks.example.test/a"), false, true); a.code != http.StatusUnauthorized || len(endpointsOf(mine.ID)) != 0 {
		t.Fatalf("a create with no session: %d, endpoints %v", a.code, endpointsOf(mine.ID))
	}
	// No CSRF token: refused before the handler.
	if a := send(http.MethodPost, "/webhooks/create", as(mine.ID, "url", "https://hooks.example.test/a"), true, false); a.code != http.StatusForbidden || len(endpointsOf(mine.ID)) != 0 {
		t.Fatalf("a create with no CSRF token: %d", a.code)
	}
	// Malformed: a URL that is not one, one with credentials, an event the node does not send.
	for _, c := range []struct{ url, events, reason string }{
		{"not a url", "", webhooks.NotAURL},
		{"https://user:pw@hooks.example.test/a", "", webhooks.HasCredentials},
		{"https://hooks.example.test/" + strings.Repeat("a", webhooks.MaxURLBytes), "", webhooks.URLTooLong},
		{"https://hooks.example.test/a", "message.received,contact.removed", webhooks.UnknownEvent},
	} {
		a := send(http.MethodPost, "/webhooks/create", as(mine.ID, "url", c.url, "events", c.events), true, true)
		if a.code != http.StatusBadRequest || a.body["error"] != "bad_request" || a.body["reason"] != c.reason || a.body["detail"] == "" {
			t.Fatalf("create %q %q: %d %v; want 400 bad_request %s", c.url, c.events, a.code, a.body, c.reason)
		}
	}
	if len(endpointsOf(mine.ID)) != 0 {
		t.Fatal("a refused registration stored an endpoint")
	}

	// The control: the owner's own endpoint, registered, its secret answered once and listed without it.
	made := send(http.MethodPost, "/webhooks/create", as(mine.ID, "url", "http://agent:4111/hdtp/webhook", "events", "message.received, request.pending"), true, true)
	secret, _ := made.body["secret"].(string)
	endpoint, _ := made.body["endpoint"].(map[string]any)
	if made.code != http.StatusOK || !strings.HasPrefix(secret, "whsec_") || endpoint == nil {
		t.Fatalf("create: %d %v", made.code, made.body)
	}
	id, _ := endpoint["id"].(string)
	if got, _ := endpoint["events"].([]any); len(got) != 2 {
		t.Fatalf("the filter was stored as %v; want the two names the form listed", endpoint["events"])
	}
	listed := send(http.MethodGet, "/api/webhooks", as(mine.ID), true, false)
	raw, _ := json.Marshal(listed.body)
	if listed.code != http.StatusOK || !strings.Contains(string(raw), id) || strings.Contains(string(raw), secret) || strings.Contains(string(raw), theirEndpoint.ID) {
		t.Fatalf("list: %d %s", listed.code, raw)
	}
	if evs, _ := listed.body["events"].([]any); len(evs) != len(webhooks.Subscribable()) {
		t.Fatalf("the page offers %v; want every name the node sends", listed.body["events"])
	}

	routes := []struct {
		method, path string
		kv           []string
	}{
		{http.MethodGet, "/api/webhooks/%s/deliveries", nil},
		{http.MethodPost, "/webhooks/%s/rotate", nil},
		{http.MethodPost, "/webhooks/%s/status", []string{"status", "paused"}},
		{http.MethodPost, "/webhooks/%s/remove", nil},
	}
	path := func(p, id string) string { return strings.Replace(p, "%s", url.PathEscape(id), 1) }
	for _, r := range routes {
		// An endpoint that does not exist, and another account's under one's own: both not found.
		for _, target := range []string{"whe_00000000000000000000000000000000", theirEndpoint.ID} {
			if a := send(r.method, path(r.path, target), as(mine.ID, r.kv...), true, true); a.code != http.StatusNotFound || a.body["error"] != "not_found" {
				t.Fatalf("%s %s under my account: %d %v; want 404 not_found", r.method, path(r.path, target), a.code, a.body)
			}
		}
		// Their account named: 404 at account resolution, before the handler.
		if a := send(r.method, path(r.path, theirEndpoint.ID), as(theirs.ID, r.kv...), true, true); a.code != http.StatusNotFound {
			t.Fatalf("%s naming their account: %d; want 404", r.method, a.code)
		}
	}
	if got := endpointsOf(theirs.ID); len(got) != 1 || got[0].Status != "active" || got[0].RotatingUntil != nil {
		t.Fatalf("their endpoint after the refusals: %+v; want it as it was", got)
	}
	if a := send(http.MethodPost, path("/webhooks/%s/status", id), as(mine.ID, "status", "stopped"), true, true); a.code != http.StatusBadRequest || a.body["error"] != "bad_request" {
		t.Fatalf("a status that is neither: %d %v", a.code, a.body)
	}

	// Every route on the owner's own endpoint.
	if a := send(http.MethodGet, path("/api/webhooks/%s/deliveries", id), as(mine.ID), true, false); a.code != http.StatusOK {
		t.Fatalf("deliveries: %d %v", a.code, a.body)
	}
	rotated := send(http.MethodPost, path("/webhooks/%s/rotate", id), as(mine.ID), true, true)
	if s, _ := rotated.body["secret"].(string); rotated.code != http.StatusOK || !strings.HasPrefix(s, "whsec_") || s == secret || rotated.body["rotating_until"] == nil {
		t.Fatalf("rotate: %d %v", rotated.code, rotated.body)
	}
	for _, status := range []string{"paused", "active"} {
		if a := send(http.MethodPost, path("/webhooks/%s/status", id), as(mine.ID, "status", status), true, true); a.code != http.StatusOK || endpointsOf(mine.ID)[0].Status != status {
			t.Fatalf("status %s: %d %v", status, a.code, a.body)
		}
	}
	if a := send(http.MethodPost, path("/webhooks/%s/remove", id), as(mine.ID), true, true); a.code != http.StatusOK || len(endpointsOf(mine.ID)) != 0 {
		t.Fatalf("remove: %d %v", a.code, a.body)
	}
	if a := send(http.MethodPost, path("/webhooks/%s/remove", id), as(mine.ID), true, true); a.code != http.StatusNotFound {
		t.Fatalf("a second remove: %d; want 404", a.code)
	}

	// The audit rows are the service's: one per change and per refusal it decided, none from the page.
	want := []string{
		"webhook_create account:" + mine.ID + " bad_request",
		"webhook_create account:" + mine.ID + " bad_request",
		"webhook_create account:" + mine.ID + " bad_request",
		"webhook_create account:" + mine.ID + " bad_request",
		"webhook_create account:" + mine.ID + " webhook:" + id + " host:agent:4111 ok",
	}
	for _, r := range []string{"webhook_rotate", "webhook_pause", "webhook_delete"} {
		for _, target := range []string{"whe_00000000000000000000000000000000", theirEndpoint.ID} {
			want = append(want, r+" account:"+mine.ID+" webhook:"+target+" not_found")
		}
	}
	want = append(want,
		"webhook_status account:"+mine.ID+" webhook:"+id+" bad_request",
		"webhook_rotate account:"+mine.ID+" webhook:"+id+" ok",
		"webhook_pause account:"+mine.ID+" webhook:"+id+" ok",
		"webhook_resume account:"+mine.ID+" webhook:"+id+" ok",
		"webhook_delete account:"+mine.ID+" webhook:"+id+" ok",
		"webhook_delete account:"+mine.ID+" webhook:"+id+" not_found",
	)
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
}

// The endpoint past webhooks.EndpointLimit is a conflict the page answers 409 with the node's
// sentence, audited once, and nothing is stored.
func TestTheWebhooksPageRefusesTheEndpointPastTheLimit(t *testing.T) {
	ctx := context.Background()
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	var svc *webhooks.Service
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		svc = webhooks.New(st, kr, func(a, r, o string) { rows = append(rows, a+" "+r+" "+o) })
		MountWebhookPages(mux, WebhooksDeps{Webhooks: svc})
	})
	me, session := e.signIn(t, "Me")
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	for i := range webhooks.EndpointLimit {
		if _, _, err := svc.Create(ctx, mine.ID, "http://agent:4111/"+strconv.Itoa(i), nil); err != nil {
			t.Fatal(err)
		}
	}
	rows = nil
	form := url.Values{"account": {mine.ID}, "url": {"http://agent:4111/one-more"}}
	req := httptest.NewRequest(http.MethodPost, "/webhooks/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:8080"
	req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
	req.Header.Set("X-HDTP-Csrf", "tok")
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusConflict || body["error"] != "conflict" ||
		body["detail"] != "This identity has 100 endpoints, the most it can have. Remove one to add another." || body["secret"] != nil {
		t.Fatalf("the endpoint past the limit: %d %v; want 409 conflict with the node's sentence", rec.Code, body)
	}
	if list, _ := svc.List(ctx, mine.ID); len(list) != webhooks.EndpointLimit {
		t.Fatalf("%d endpoints after the refusal, want %d", len(list), webhooks.EndpointLimit)
	}
	if got, want := strings.Join(rows, "\n"), "webhook_create account:"+mine.ID+" endpoint_cap"; got != want {
		t.Fatalf("audit rows: %q, want %q", got, want)
	}
}

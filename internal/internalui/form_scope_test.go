package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// A form that fails to parse is refused before any handler. ParseForm keeps every pair that
// parsed and reports the first that did not; accountMiddleware read the body's `account` only on
// a nil error, and the handler's own ParseForm then returned nil (it returns early once the form
// is set) and formOrQuery handed it the account the check never saw. So `account=<theirs>&x=%zz`,
// or a well-formed body under `?z=%zz`, acted on another owner's account.
func TestAFormThatFailsToParseIsRefusedBeforeAnyHandler(t *testing.T) {
	ctx := context.Background()
	var sentAs []string
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountContactPages(mux, ContactsDeps{Store: st, Invalidate: func(context.Context, string, string) error { return nil }})
		MountMessagePages(mux, MessagesDeps{Store: st, Send: func(_ context.Context, account, _ string, _ messaging.Input) (messaging.Result, error) {
			sentAs = append(sentAs, account)
			return messaging.Result{}, nil
		}})
	})
	me, session := e.signIn(t, "Me")
	them, _ := e.signIn(t, "Them")
	mine, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, me, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, them, theirs.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	const fpr = "sha256:friend"
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: theirs.ID, Fingerprint: fpr, Status: "active"}); err != nil {
		t.Fatal(err)
	}

	// post is what the SPA sends: a urlencoded body, the CSRF token in the header.
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Host = "localhost:8080"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: "tok"})
		req.Header.Set("X-HDTP-Csrf", "tok")
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	untouched := func(what string) {
		t.Helper()
		c, err := e.st.GetContact(ctx, theirs.ID, fpr)
		if err != nil {
			t.Fatal(err)
		}
		if c.Status != "active" {
			t.Fatalf("%s: the other owner's contact is now %q", what, c.Status)
		}
		if len(sentAs) != 0 {
			t.Fatalf("%s: a message was sent as %v", what, sentAs)
		}
	}

	block := "/contacts/" + fpr + "/block"
	send := "/messages/send"
	sendBody := "account=" + theirs.ID + "&contact=" + fpr + "&text=hi"
	for _, c := range []struct{ name, path, body string }{
		{"block, bad pair in the body", block, "account=" + theirs.ID + "&x=%zz"},
		{"block, semicolon in the body", block, "account=" + theirs.ID + "&x=a;b"},
		{"block, bad query", block + "?z=%zz", "account=" + theirs.ID},
		{"send, bad pair in the body", send, sendBody + "&x=%zz"},
		{"send, bad query", send + "?z=%zz", sendBody},
	} {
		e.rows = nil
		rec := post(c.path, c.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "bad form") {
			t.Errorf("%s: %d %q, want 400 bad form", c.name, rec.Code, rec.Body.String())
		}
		path := strings.SplitN(c.path, "?", 2)[0]
		if !hasAuditRow(e.rows, "portal_request path:"+path+" bad_form") {
			t.Errorf("%s: no bad_form audit row in %v", c.name, e.rows)
		}
		untouched(c.name)
	}

	// Control: the same account named in a well-formed body is refused 404, as it always was.
	if rec := post(block, "account="+theirs.ID); rec.Code != http.StatusNotFound {
		t.Errorf("a well-formed body naming another owner's account: %d, want 404", rec.Code)
	}
	if rec := post(send, sendBody); rec.Code != http.StatusNotFound {
		t.Errorf("a well-formed send naming another owner's account: %d, want 404", rec.Code)
	}
	untouched("control")
	// And a well-formed body naming the owner's own account gets through.
	if rec := post(send, "account="+mine.ID+"&contact="+fpr+"&text=hi"); rec.Code != http.StatusSeeOther || len(sentAs) != 1 || sentAs[0] != mine.ID {
		t.Errorf("the owner's own send: %d, sent as %v", rec.Code, sentAs)
	}
}

// csrfMiddleware reads the token from the form when the header is absent; a form that fails to
// parse is refused there, not judged by the pairs that happened to parse.
func TestCSRFRefusesAFormThatFailsToParse(t *testing.T) {
	aud := &recAudit{}
	reached := false
	h := csrfMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }), aud.fn)
	for _, body := range []string{"csrf=tok&x=%zz", "csrf=tok"} {
		reached = false
		aud.rows = nil
		req := httptest.NewRequest(http.MethodPost, "/contacts/add", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: csrfCookieName(), Value: "tok"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		bad := strings.Contains(body, "%zz")
		if bad && (reached || rec.Code != http.StatusBadRequest || !aud.hasRow("portal_request", "path:/contacts/add", "bad_form")) {
			t.Errorf("%q: reached %v, %d, rows %v; want 400 bad_form", body, reached, rec.Code, aud.rows)
		}
		if !bad && !reached {
			t.Errorf("%q: a well-formed form with the right token was refused: %d", body, rec.Code)
		}
	}
}

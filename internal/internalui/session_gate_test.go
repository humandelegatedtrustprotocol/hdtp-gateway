package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// SPEC §8.3: a session on every bind, and the session gate is an allow-list. What it serves without
// a session is the sign-in and setup ceremonies, /api/session, the wallet's return page, the static
// shell and the SPA's views (code, not data). Every other route is refused: a GET of a data route
// used to fall through to its handler, so `GET /media/{hash}?account=<id>` answered the stored bytes
// and `GET /events?account=<id>` opened that account's event stream to anyone who could reach the
// portal. A browser's GET is sent to sign in and back; a fetch under /api/ and every mutation is 401.
func TestTheSessionGateIsAnAllowList(t *testing.T) {
	ctx := context.Background()
	blobs := messaging.BlobDir{Root: t.TempDir()}
	hash, err := blobs.Put([]byte("the stored bytes"))
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountMediaPages(mux, MediaDeps{Store: st, Blobs: blobs})
		MountInboxPages(mux, InboxDeps{Store: st, Bus: messaging.NewBus(st)})
		MountWalletPages(mux, WalletDeps{Store: st})
		MountIntegrationPages(mux, IntegrationsDeps{Store: st, Background: joined(t)})
		mux.HandleFunc("GET /probe", func(w http.ResponseWriter, r *http.Request) {
			reached = append(reached, r.URL.Path)
		})
	})
	owner, session := e.signIn(t, "Me")
	mine, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddMembership(ctx, owner, mine.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertBlob(ctx, store.Blob{AccountID: mine.ID, Hash: hash, Filename: "report.txt", Mime: "text/plain", Size: 16}); err != nil {
		t.Fatal(err)
	}

	// get issues a GET with a short-lived context: the event stream holds its request open until
	// the context ends, and a refusal answers before it does.
	get := func(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		req.Host = "localhost:8080"
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	media := "/media/" + hash + "?account=" + mine.ID
	events := "/events?account=" + mine.ID

	// No session: a browser's GET of a data route is sent to sign in, with the page to come back to,
	// and carries none of the data.
	for _, path := range []string{media, events, "/probe"} {
		e.rows = nil
		rec := get(path)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?next="+url.QueryEscape(path) {
			t.Errorf("GET %s with no session: %d %q, body %q", path, rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "the stored bytes") || strings.Contains(rec.Body.String(), "connected") {
			t.Errorf("GET %s with no session served data: %q", path, rec.Body.String())
		}
		if !hasAuditRow(e.rows, "portal_request path:"+strings.SplitN(path, "?", 2)[0]+" identity_required") {
			t.Errorf("GET %s with no session was not audited as refused: %v", path, e.rows)
		}
	}
	if len(reached) != 0 {
		t.Errorf("a registered route was reached with no session: %v", reached)
	}
	// A mutation with no session stays 401, and a fetch under /api/ answers JSON the SPA routes on.
	if rec := e.do(t, http.MethodPost, "/media/fetch", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("POST with no session: %d", rec.Code)
	}
	if rec := get("/api/inbox?account=" + mine.ID); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "identity_required") {
		t.Errorf("GET /api/inbox with no session: %d %q", rec.Code, rec.Body.String())
	}

	// The views and the shell serve without a session, and without a refusal row: the sign-in page
	// is one of them.
	for _, path := range []string{"/", "/login", "/contacts", "/inbox", "/assets/index-abc.js"} {
		e.rows = nil
		rec := get(path)
		if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
			t.Errorf("GET %s with no session: %d", path, rec.Code)
		}
		if hasAuditRow(e.rows, "portal_request") {
			t.Errorf("GET %s, a view, was audited as refused: %v", path, e.rows)
		}
	}

	// The two pages a browser arrives at from another site reach their handlers without a session
	// and without a refusal row: the wallet's return page renders, and the OAuth callback answers
	// its own refusal of a state nothing is pending for.
	e.rows = nil
	if rec := get("/wallet/return"); rec.Code != http.StatusOK {
		t.Errorf("GET /wallet/return with no session: %d", rec.Code)
	}
	if rec := get("/oauth/callback?code=x&state=NOPE"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no authorization is pending") {
		t.Errorf("GET /oauth/callback with no session: %d %q", rec.Code, rec.Body.String())
	}
	if hasAuditRow(e.rows, "portal_request") {
		t.Errorf("an open page was audited as refused: %v", e.rows)
	}

	// The control: with the session, the same routes answer.
	if rec := get(media, session); rec.Code != http.StatusOK || rec.Body.String() != "the stored bytes" {
		t.Errorf("GET %s with a session: %d %q", media, rec.Code, rec.Body.String())
	}
	if rec := get(events, session); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ": connected") {
		t.Errorf("GET %s with a session: %d %q", events, rec.Code, rec.Body.String())
	}
	if rec := get("/probe", session); rec.Code != http.StatusOK || len(reached) != 1 {
		t.Errorf("GET /probe with a session: %d, reached %v", rec.Code, reached)
	}
}

func hasAuditRow(rows []string, prefix string) bool {
	for _, r := range rows {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

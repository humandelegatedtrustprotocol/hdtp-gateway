package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// An invite is a link you send someone. The page showed only the PATH —
// `/i/<token>` — because ManageDeps.PublicURL was never wired in compose.go and
// stayed the empty string, so `{{.PublicURL}}/i/{{.NewToken}}` rendered as a bare
// path. What the owner could copy was not something anyone could open.
//
// It is a func now rather than a string, for the same reason Card is: the public
// URL is live-changeable from Settings, so a value captured once at wiring time
// would be stale from the first change.
func TestANewInviteIsShownAsALinkSomebodyCanOpen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{
		Store:     e.st,
		PublicURL: func() string { return "https://alice.example.com" },
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/invites?account="+acct.ID, nil)
	req.RemoteAddr = "127.0.0.1:5555"
	mux.ServeHTTP(rr, req)

	// The API must hand the SPA a LIVE public URL — the func is called per
	// request, so a Settings change reaches the very next render — and the SPA
	// builds `${public_url}/i/${token}` from it (web/src/views/invites.tsx).
	body := rr.Body.String()
	if !strings.Contains(body, `"public_url":"https://alice.example.com"`) {
		t.Errorf("the invites payload carries no usable public URL: %s", firstN(body, 400))
	}
}

// With no public URL configured there is no link to give out, and saying so is
// better than handing over a path that silently goes nowhere.
func TestAnInviteWithoutAPublicURLSaysSoRatherThanShowingAPath(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	acct, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountManagePages(mux, ManageDeps{Store: e.st, PublicURL: func() string { return "" }})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/invites?account="+acct.ID, nil)
	req.RemoteAddr = "127.0.0.1:5555"
	mux.ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), `"public_url":""`) {
		t.Errorf("the API pretends there is a public URL: %s", firstN(rr.Body.String(), 400))
	}
	// The SPA's half of the rule: with no public URL it must explain, never
	// offer a bare path as if it were shareable.
	// Contacts, requests and invites are one tabbed page now; the invites tab
	// lives in people.tsx.
	src, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "views", "people.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "no public URL") {
		t.Error("the invites tab cannot tell the owner why there is no link to copy")
	}
	if strings.Contains(string(src), "`/i/${") {
		t.Error("the invites tab offers a bare /i/ path; nobody can open that")
	}
}

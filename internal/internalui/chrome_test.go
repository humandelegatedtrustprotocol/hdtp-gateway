package internalui

// The portal's chrome — brand, navigation, sign-out — is one React component
// now (web/src/app.tsx), so the defect this file used to lint per template (a
// page shipped without the shell, or with a private copy of the palette) is
// structurally impossible: there is one shell and one stylesheet, and every
// view renders inside them. What remains worth holding at this layer:
//
//  1. every navigation route must SERVE the shell — the history fallback is
//     what makes a deep link or a refresh on /contacts work at all;
//  2. no Go-rendered form may put the account in a URL (the owner's rule:
//     nothing about which identity you act as belongs in the address bar), and
//     the SPA may not either;
//  3. the compiled bundle must actually contain the portal — an empty dist
//     embeds and serves 200s while every view is blank.

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/web"
)

// The routes the shell's navigation offers. A route here that stops serving the
// shell breaks every bookmark and refresh on it.
var navRoutes = []string{
	"/", "/messages", "/contacts", "/requests", "/invites", "/card",
	"/integrations", "/settings", "/identity", "/owners", "/audit",
	"/login",
	// NOT /setup: that route serves the shell only through the §8.6 gate
	// (loopback or one-time token at zero passkeys), tested in server_test.go.
}

func TestEveryNavRouteServesTheShell(t *testing.T) {
	h := newEnv(t).h
	for _, route := range navRoutes {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d — a refresh or deep link on this route is broken", route, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), "/assets/") {
			t.Errorf("%s did not serve the SPA shell", route)
		}
	}
}

// The bundle must carry every affordance the views promise. This is the other
// half of the API-level tests: /api/contacts says `can_add`, and THIS says the
// code that renders the form for it actually shipped. An empty or stale dist
// embeds silently and serves 200s.
func TestBundleCarriesTheViews(t *testing.T) {
	js := bundleJS(t)
	for _, want := range []string{
		"invite_url",     // accepting an invite (contacts view)
		"/messages/send", // the composer
		"/invites/create",
		"petname",
		"/owners/tokens/create",
		"pact_csrf", // the double-submit read
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the compiled portal does not mention %q — the view that uses it did not ship", want)
		}
	}
	// And the reverse, which is how a STALE dist shows itself. `web/dist` is committed, the
	// portal is built by `make web`, and `make check` does not run that — so when the 1.x removal
	// deleted the key-rotation view from `web/src`, and a leftover `posture.gateway` broke the
	// TypeScript build, nobody rebuilt. The binary went on embedding a portal with the rotation
	// view in it, calling a route the server no longer has, and this test kept that green: its
	// list REQUIRED "/identity/rotate". Nothing the server cannot answer may be in the bundle.
	for _, gone := range []string{
		"/identity/rotate", // 1.x key rotation: no route serves it
		"X-PACT-KEY",       // a card carries a certificate; no property by this name
		"X-PACT-ENDPOINT",  // the address is in the leaf the wallet issues
		"my gateway",       // the relay role's dashboard cell
	} {
		if strings.Contains(js, gone) {
			t.Errorf("the compiled portal still mentions %q, which nothing serves — web/dist is stale: run `make web`", gone)
		}
	}
}

func bundleJS(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	err := fs.WalkDir(web.Dist, "dist", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		b, rerr := fs.ReadFile(web.Dist, p)
		if rerr != nil {
			return rerr
		}
		all.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if all.Len() == 0 {
		t.Fatal("the embedded dist holds no JavaScript; run `make web` and commit web/dist")
	}
	return all.String()
}

func repoRootUI(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// The owner's rule, kept from the server-rendered portal: nothing about which
// identity you act as belongs in the address bar. Go-rendered forms must carry
// it in the body, and the SPA must not navigate() or Link to a URL naming it.
func TestNoFormPutsTheAccountInTheURL(t *testing.T) {
	root := repoRootUI(t)
	bad := regexp.MustCompile(`action="[^"]*\?account=`)
	err := filepath.WalkDir(filepath.Join(root, "internal", "internalui"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bad.MatchString(line) {
				t.Errorf("%s:%d puts the account in a form action, so it lands in the "+
					"address bar. Carry it as a body field; the middleware reads the form body.",
					filepath.Base(p), i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The SPA side of the same rule, checked in the source (the bundle mangles
	// nothing here: navigate("...") strings survive minification).
	spaBad := regexp.MustCompile(`(navigate|to=)[("'\x60{]+[^)\n]*[?&]account=`)
	err = filepath.WalkDir(filepath.Join(root, "web", "src"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".tsx") && !strings.HasSuffix(p, ".ts") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(b), "\n") {
			if spaBad.MatchString(line) {
				t.Errorf("web/src/%s:%d navigates to a URL naming the account; it would land "+
					"in the address bar. The selection lives in api.ts, not in routes.",
					filepath.Base(p), i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// First run over a non-loopback bind arrives as `/?token=…`, and the wizard's
// gate refuses without that token (§8.6). The shell redirects an unclaimed node
// to /setup — so if that redirect drops the query string, it sends the owner
// from a working link to a refusal, and there is no longer a loopback carve-out
// to mask it. The redirect must carry location.search.
func TestTheSetupRedirectKeepsTheSetupToken(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "app.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, `navigate("/setup" + location.search)`) {
		t.Error("the shell's redirect to the wizard does not carry location.search; " +
			"a non-loopback first run would lose its one-time setup token")
	}
	if strings.Contains(src, `navigate("/setup")`) {
		t.Error("a bare navigate(\"/setup\") drops the setup token")
	}
}

// The capabilities this session found missing, held where they live: the
// compiled bundle. Each was reachable on the server and unreachable by a person.
func TestBundleCarriesTheAffordancesThatWentMissing(t *testing.T) {
	js := bundleJS(t)
	for _, want := range []struct{ frag, why string }{
		{"/media/", "a contact's file: the conversation view rendered its JSON body as prose"},
		{"/media/fetch", "the deliberate, owner-initiated fetch of a contact-supplied URL (§7.5)"},
		{"/settings/pair", "pairing with an ingress on your own domain (§10)"},
		{"/settings/unpair", "undoing that pairing"},
		{"/identity/create", "a second identity, which was CLI-only while the shell offered a switcher"},
	} {
		if !strings.Contains(js, want.frag) {
			t.Errorf("the compiled portal cannot reach %s — %s", want.frag, want.why)
		}
	}
}

// Contacts, requests and invites are one tabbed page. Merging pages is how an
// affordance quietly disappears, so the three things that must survive it are
// checked here rather than assumed.
func TestTheCombinedContactsPageKeepsAllThreeSubjects(t *testing.T) {
	js := bundleJS(t)

	// 1. Each tab's own work is still reachable. (The route→UI lint proves the
	//    server routes are named somewhere; this proves they are named on the
	//    page that replaced three pages.)
	for _, frag := range []string{"/contacts/add", "/invites/create", "/approve", "/reject", "/revoke"} {
		if !strings.Contains(js, frag) {
			t.Errorf("the combined page lost %s", frag)
		}
	}

	// 2. A pending request used to be a top-level nav item. Behind a tab it is
	//    invisible unless the tab says so, and somebody waiting to reach you is
	//    exactly the thing that must not go unnoticed.
	if !strings.Contains(js, "urgent") {
		t.Error("the requests tab carries no waiting count — a pending request is now invisible")
	}

	// 3. All three routes must still resolve, so the dashboard's "waiting" link
	//    and any bookmark keep working. (Served-ness is TestEveryNavRouteServesTheShell;
	//    this is the client-side half that picks the tab.)
	for _, route := range []string{"/contacts", "/requests", "/invites"} {
		if !strings.Contains(js, route) {
			t.Errorf("the SPA no longer routes %s", route)
		}
	}
}

package scenario

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Everything an owner must be able to DO from the portal, checked on a real node.
//
// Seven defects in one evening had the same shape: a working endpoint with no way
// for a person to reach it — pages the dashboard linked to that answered 404, an
// invite rendered as a path nobody could open, a logout route no button posted to,
// a header on one page out of thirteen, redeeming an invite that existed only on
// the agent surface, and an integration that could be created empty and never
// removed. Every one had a passing test that called the endpoint directly.
//
// So this asserts the affordances, not the endpoints. It is the check that would
// have caught all seven.
func TestPortalOffersEveryAffordanceAnOwnerNeeds(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	p, err := SetupPaired(ctx, "pactaff", Ports{Owner: "18661", Public: "18662"}, nodeImage)
	t.Cleanup(func() { p.Teardown(os.Getenv("PACT_HARNESS_ARTIFACTS")) })
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	base := "http://localhost:" + p.OwnerPort

	// 1. The shell is on EVERY page the dashboard offers, not just the dashboard.
	for _, href := range dashboardLinks(ctx, t, base) {
		code, body := httpGet(ctx, t, base+href)
		if code == 404 || code == 400 {
			t.Errorf("%s answers %d — the dashboard links to a page that cannot be opened", href, code)
			continue
		}
		if !strings.Contains(body, `class="brand"`) || !strings.Contains(body, "<nav>") {
			t.Errorf("%s renders with no shell: nothing to navigate with, no way out", href)
		}
	}

	// 2. An invite is a LINK, not a path: it must carry the node's public base.
	code, body := httpGet(ctx, t, base+"/invites")
	if code != 200 {
		t.Fatalf("/invites: %d", code)
	}
	if !strings.Contains(body, `action="/invites/create"`) {
		t.Error("no way to create an invite")
	}

	// 3. Accepting somebody else's invite — the direction that only existed on the
	//    owner MCP.
	code, body = httpGet(ctx, t, base+"/contacts")
	if code != 200 {
		t.Fatalf("/contacts: %d", code)
	}
	if !strings.Contains(body, `action="/contacts/add"`) || !strings.Contains(body, `name="invite_url"`) {
		t.Errorf("no way to accept an invite from Contacts: %s", shorten(body, 300))
	}

	// 4. Integrations: junk cannot be created, and what exists can be removed.
	code, body = httpGet(ctx, t, base+"/integrations")
	if code != 200 {
		t.Fatalf("/integrations: %d", code)
	}
	if !strings.Contains(body, `action="/integrations/create"`) {
		t.Error("no way to add an integration")
	}
	// An empty submission must be refused rather than creating a row that shows
	// as `— streamable-http — disabled` and can never be removed.
	if code := portalPost(ctx, t, base+"/integrations/create", url.Values{
		"transport": {"streamable-http"},
	}); code == 303 || code == 200 {
		t.Errorf("an integration with no slug and nothing to dial was accepted (%d)", code)
	}
	// A real one can be added, and offers a way out.
	if code := portalPost(ctx, t, base+"/integrations/create", url.Values{
		"slug": {"probe"}, "transport": {"streamable-http"},
		"endpoint": {"https://example.invalid/mcp"}, "auth_kind": {"none"},
	}); code != 303 {
		t.Fatalf("a valid integration was refused: %d", code)
	}
	_, body = httpGet(ctx, t, base+"/integrations")
	if !strings.Contains(body, "/remove") {
		t.Errorf("an integration cannot be removed: %s", shorten(body, 400))
	}
	// 5. Messaging has a way IN. It worked end to end and could only be reached
	//    from a thread that already existed, so an owner could reply and never
	//    start a conversation.
	code, body = httpGet(ctx, t, base+"/messages")
	if code != 200 {
		t.Fatalf("/messages: %d", code)
	}
	// The fingerprint is URL-escaped inside the href (`sha256%3a…`), which is
	// correct, so match the link rather than the raw value.
	if !strings.Contains(body, `href="/messages?contact=`) {
		t.Errorf("the conversation view lists no contact to talk to: %s", shorten(body, 300))
	}
	code, body = httpGet(ctx, t, base+"/messages?contact="+p.Contact.Fingerprint())
	if code != 200 || !strings.Contains(body, `action="/messages/send"`) {
		t.Errorf("picking a contact offers no way to send: %d %s", code, shorten(body, 300))
	}

	// 6. And a conversation can be ENDED, not only started.
	_, body = httpGet(ctx, t, base+"/contacts/"+p.Contact.Fingerprint())
	if !strings.Contains(body, "/remove") {
		t.Errorf("a contact cannot be removed: %s", shorten(body, 300))
	}

	t.Log("portal: every page wears the shell, invites can be created and accepted, " +
		"integrations are validated and removable, conversations can be started")
}

// portalPost submits a form to the portal, carrying the CSRF token the page set.
// Every mutating request needs one even on a loopback bind (SPEC §8.3).
func portalPost(ctx context.Context, t *testing.T, target string, form url.Values) int {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second,
		// Report the redirect rather than following it: 303 is the success signal.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// A GET first, to be handed the CSRF cookie.
	seed, err := http.NewRequestWithContext(ctx, http.MethodGet, originOf(target)+"/settings", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(seed)
	if err != nil {
		t.Fatalf("seeding the CSRF cookie: %v", err)
	}
	res.Body.Close()
	token := ""
	for _, ck := range jar.Cookies(res.Request.URL) {
		if ck.Name == "pact_csrf" {
			token = ck.Value
		}
	}
	if token == "" {
		t.Fatal("the portal set no CSRF cookie")
	}
	form.Set("csrf", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Pact-Csrf", token)
	out, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer out.Body.Close()
	return out.StatusCode
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

package internalui

// The way out, and when it is offered. In the server-rendered portal these were
// template assertions; the shell is one React component now, so the division of
// labour is: /api/session must SAY the truth (signed_in / login_required), and
// the bundle must carry both states the shell renders from it — the sign-out
// button, and the loopback explanation for why there is none. The POST /logout
// endpoint itself (a POST, CSRF-gated, session-ending) is exercised end to end
// by TestPortalRegistrationAndLoginCeremony.

import (
	"context"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignedInOwnerIsOfferedAWayOut(t *testing.T) {
	js := bundleJS(t)
	if !strings.Contains(js, "Sign out") {
		t.Error("the compiled shell has no sign-out affordance")
	}
	if !strings.Contains(js, "/logout") {
		t.Error("the compiled shell never posts to /logout")
	}
}

// There is no third state. The shell once had one — "local access — no
// sign-in", shown on a loopback bind, which served the whole portal to anyone
// who could open the socket and made a registered passkey optional in practice.
// §8.3 now requires a session on every bind, so the shell offers exactly two
// things: a way out when signed in, a way in when not.
func TestTheShellOffersOnlySignInOrSignOut(t *testing.T) {
	js := bundleJS(t)
	if strings.Contains(js, "local access") || strings.Contains(js, "no sign-in") {
		t.Error("the shell still renders the no-login state; a loopback portal now needs a session too")
	}
	if !strings.Contains(js, "Sign in") {
		t.Error("the shell offers no way in for a caller without a session")
	}
}

// And the API must not advertise a knob that no longer exists: a `login_required`
// that could only ever be true is a field a client can get wrong.
func TestSessionPayloadDoesNotClaimLoginIsOptional(t *testing.T) {
	e := newEnv(t)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if strings.Contains(rec.Body.String(), "login_required") {
		t.Errorf("the session payload still carries login_required: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"signed_in":false`) {
		t.Errorf("the session payload does not report the absent session: %s", rec.Body.String())
	}
}

// /api/session is served without a session on purpose — the sign-in and wizard
// views render from it. That makes it the one open window onto the node, so it
// must not enumerate what the node holds: an unauthenticated caller has proven
// nothing and is owed nothing but "sign in" or "set up". It used to answer with
// every account, slug and identity fingerprint, which went unnoticed while a
// loopback portal served the whole thing with no login anyway.
func TestSessionEndpointDoesNotEnumerateIdentities(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.CreateAccount(ctx, store.CreateAccountParams{
		Slug: "secret-slug", DisplayName: "Secret Person", Algo: "p256"}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	body := rec.Body.String()

	for _, leak := range []string{"secret-slug", "Secret Person"} {
		if strings.Contains(body, leak) {
			t.Errorf("an unauthenticated /api/session leaked %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, `"accounts":[]`) {
		t.Errorf("accounts should be empty without a session: %s", body)
	}
}

// Two nodes on one host must not sign each other's owners out.
//
// Cookies are scoped by host and path and NEVER by port (RFC 6265 §8.5), so
// `localhost:18120` and `localhost:18121` share one jar. With a single fixed
// cookie name, whichever node logged in last owned the only `pact_session`
// entry and the other owner was signed out having done nothing — which is
// exactly what happened on the demo pair: every `identity_required` on one node
// lined up with a successful login on the other, and it read as the portal
// dropping sessions at random.
//
// Nothing in the request/response tests could see it: each ran against one node.
// The property is about two, so it is checked as a property of the NAMES.
func TestTwoNodesOnOneHostDoNotShareCookieNames(t *testing.T) {
	// The demo pair: identical container layout, different public URLs.
	alice := core.NodeTag("/data", "https://alice.example.com", "127.0.0.1:8080")
	bob := core.NodeTag("/data", "https://bob.example.com", "127.0.0.1:8080")

	SetCookieTag(alice)
	aSession, aCSRF := sessionCookieName(), csrfCookieName()
	SetCookieTag(bob)
	bSession, bCSRF := sessionCookieName(), csrfCookieName()
	t.Cleanup(func() { SetCookieTag("") })

	if aSession == bSession {
		t.Errorf("both nodes write the session cookie %q — logging into one signs the other out", aSession)
	}
	// The csrf cookie needs the same treatment: a clobbered one makes every
	// mutation fail the double-submit check while the page holds the old value.
	if aCSRF == bCSRF {
		t.Errorf("both nodes write the csrf cookie %q — one node's forms stop working", aCSRF)
	}
	for _, name := range []string{aSession, bSession, aCSRF, bCSRF} {
		if strings.ContainsAny(name, " ;,=") {
			t.Errorf("%q is not a usable cookie name", name)
		}
	}

	// A single node with no tag keeps the plain names, so nothing changes for
	// the ordinary one-node case.
	SetCookieTag("")
	if sessionCookieName() != "pact_session" || csrfCookieName() != "pact_csrf" {
		t.Errorf("an untagged node changed its cookie names: %q %q", sessionCookieName(), csrfCookieName())
	}
}

// The page has to be told which csrf cookie is its own, or it picks the first
// match and every mutation fails on the node that did not write it.
func TestSessionTellsThePageItsCookieTag(t *testing.T) {
	SetCookieTag("deadbeef")
	t.Cleanup(func() { SetCookieTag("") })
	e := newEnv(t)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))
	if !strings.Contains(rec.Body.String(), `"cookie_tag":"deadbeef"`) {
		t.Errorf("the session payload does not name this node's cookies: %s", rec.Body.String())
	}
	if !strings.Contains(bundleJS(t), "cookie_tag") {
		t.Error("the compiled portal ignores the cookie tag; it would read another node's csrf cookie")
	}
}

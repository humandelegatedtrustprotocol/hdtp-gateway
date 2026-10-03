package integrations

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// SPEC §6.3: CIMD, else a pre-registered client, else — last resort — dynamic
// registration. A handler with only the last resort configured must build;
// one with nothing must say so rather than time out later.
func TestOAuthHandlerFallsBackToDynamicRegistration(t *testing.T) {
	fetch := func(context.Context, *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		return nil, errors.New("unused")
	}
	_, err := NewOAuthHandler("i1", OAuthSetup{RedirectURL: "http://localhost:18120/oauth/callback", Fetch: fetch})
	if err == nil || !strings.Contains(err.Error(), "dynamic registration") {
		t.Fatalf("no client identity configured must be refused with a message that names the options, got %v", err)
	}
	h, err := NewOAuthHandler("i1", OAuthSetup{
		RedirectURL: "http://localhost:18120/oauth/callback", Fetch: fetch,
		DynamicRegistration: &oauthex.ClientRegistrationMetadata{RedirectURIs: []string{"http://localhost:18120/oauth/callback"}, TokenEndpointAuthMethod: "none"},
	})
	if err != nil || h == nil {
		t.Fatalf("dynamic registration alone must be enough to build the handler: %v", err)
	}
}

// A flow that cannot start must tell the waiting portal request why, at once.
// Before, the owner waited out a 15 s timeout and read a message with no cause.
func TestFailReachesTheWaitingAuthorizeRequest(t *testing.T) {
	c := &Connector{}
	c.Fail("i1", errors.New("integrations: i1 has no OAuth client registered"))
	start := time.Now()
	_, err := c.AuthorizeURL(context.Background(), "i1", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "no OAuth client") {
		t.Fatalf("the failure did not reach the waiting request: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the failure was delivered only by timeout")
	}
	// The newest failure replaces a stale unread one.
	c.Fail("i2", errors.New("first"))
	c.Fail("i2", errors.New("second"))
	if _, err := c.AuthorizeURL(context.Background(), "i2", time.Second); err == nil || err.Error() != "second" {
		t.Fatalf("stale failure served instead of the newest: %v", err)
	}
}

// The browser's origin is what the provider must redirect back to.
func TestConnectorRemembersTheBrowserOrigin(t *testing.T) {
	c := &Connector{}
	if c.Origin("x") != "" {
		t.Fatal("origin known before any request")
	}
	c.SetOrigin("x", "http://localhost:18120")
	if c.Origin("x") != "http://localhost:18120" {
		t.Fatalf("origin not kept: %q", c.Origin("x"))
	}
}

// A 401 is an authentication problem whatever the row was configured with.
// It also fires OnAuthError — the change feed's needs_attention hangs off that
// hook, so a silent transition would mean an owner never told.
func TestAnyAuthFailureLandsInAuthError(t *testing.T) {
	var told []string
	m := &Manager{OnAuthError: func(id string) { told = append(told, id) }}
	for _, kind := range []string{"none", "static", "oauth"} {
		got := m.failStatus(store.Integration{ID: "int-" + kind, Slug: "s", AuthKind: kind}, errors.New("failed to connect: Unauthorized"))
		if got != "auth_error" {
			t.Errorf("auth kind %s: a 401 landed in %q, want auth_error", kind, got)
		}
	}
	if len(told) != 3 || told[0] != "int-none" {
		t.Errorf("OnAuthError heard %v, want one call per auth failure", told)
	}
	if got := m.failStatus(store.Integration{ID: "int-net", Slug: "s", AuthKind: "none"}, errors.New("dial tcp: connection refused")); got != "unreachable" {
		t.Errorf("a network failure must stay unreachable, got %q", got)
	}
	if len(told) != 3 {
		t.Errorf("OnAuthError fired for a network failure: %v", told)
	}
}

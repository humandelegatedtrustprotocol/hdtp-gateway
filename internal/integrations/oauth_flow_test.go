package integrations

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
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

// A 401 is an authentication problem whatever the row was configured with. Moving into auth_error
// fires OnAuthError and audits integration_auth once — the change feed's needs_attention hangs off
// that hook, so a silent transition would mean an owner never told. A row already in auth_error that
// fails the same way again is not a transition: neither fires, or every health cycle against a dead
// token ended every wait on the change feed. A network failure is unreachable and fires nothing.
func TestAnyAuthFailureLandsInAuthError(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	var told []string
	aud := &auditRec{}
	m := &Manager{Store: st, Audit: aud.fn, OnAuthError: func(id string) { told = append(told, id) }}
	row := func(slug, kind, status string) store.Integration {
		in, err := st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: slug, Transport: "streamable-http", Endpoint: "https://x.example/mcp", AuthKind: kind})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateIntegrationStatus(ctx, in.ID, status); err != nil {
			t.Fatal(err)
		}
		in.Status = status
		return in
	}
	landed := func(in store.Integration) string {
		got, err := st.GetIntegrationByID(ctx, in.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Status
	}
	unauthorized := errors.New("failed to connect: Unauthorized")
	var want []string
	for _, c := range []struct{ kind, status string }{{"none", "connecting"}, {"static", "ok"}, {"oauth", "unreachable"}} {
		in := row("s-"+c.kind, c.kind, c.status)
		m.landFailure(ctx, in, unauthorized)
		if got := landed(in); got != "auth_error" {
			t.Errorf("auth kind %s from %s: a 401 landed in %q, want auth_error", c.kind, c.status, got)
		}
		want = append(want, in.ID)
	}
	if !slices.Equal(told, want) || len(aud.rows) != 3 {
		t.Errorf("moving into auth_error: OnAuthError heard %v, want %v; audit %v", told, want, aud.rows)
	}
	stuck := row("s-stuck", "oauth", "auth_error")
	m.landFailure(ctx, stuck, unauthorized)
	if got := landed(stuck); got != "auth_error" || len(told) != 3 || len(aud.rows) != 3 {
		t.Errorf("a row already in auth_error failing again: landed %q, OnAuthError heard %v, audit %v; want neither to move", got, told, aud.rows)
	}
	net := row("s-net", "none", "ok")
	m.landFailure(ctx, net, errors.New("dial tcp: connection refused"))
	if got := landed(net); got != "unreachable" || len(told) != 3 {
		t.Errorf("a network failure: landed %q, OnAuthError heard %v", got, told)
	}
}

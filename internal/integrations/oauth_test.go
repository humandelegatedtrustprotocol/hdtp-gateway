package integrations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// fakeAS is a minimal RFC 8414 authorization server: PKCE S256 verified on
// exchange, RFC 8707 resource demanded on both requests, RFC 9207 iss emitted
// (overridable to test mismatch aborts), refresh grant rotates tokens.
type fakeAS struct {
	srv         *httptest.Server
	issOverride string

	mu        sync.Mutex
	challenge string
	resource  []string // resource params seen (authorize, token)
	code      string
	accessSeq int
	refreshes int
	valid     map[string]bool // currently valid access tokens
	refreshOK map[string]bool // issued refresh tokens (grace overlap, like real ASes)
}

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	a := &fakeAS{valid: map[string]bool{}, refreshOK: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oauthex.AuthServerMeta{
			Issuer:                        a.srv.URL,
			AuthorizationEndpoint:         a.srv.URL + "/authorize",
			TokenEndpoint:                 a.srv.URL + "/token",
			JWKSURI:                       a.srv.URL + "/jwks",
			ResponseTypesSupported:        []string{"code"},
			GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
			CodeChallengeMethodsSupported: []string{"S256"},
			AuthorizationResponseIssParameterSupported: true,
			TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post"},
		})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		a.mu.Lock()
		a.challenge = q.Get("code_challenge")
		if res := q.Get("resource"); res != "" {
			a.resource = append(a.resource, res)
		}
		a.code = "code-1"
		a.mu.Unlock()
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "PKCE S256 required", http.StatusBadRequest)
			return
		}
		iss := a.srv.URL
		if a.issOverride != "" {
			iss = a.issOverride
		}
		u, _ := url.Parse(q.Get("redirect_uri"))
		v := u.Query()
		v.Set("code", "code-1")
		v.Set("state", q.Get("state"))
		v.Set("iss", iss)
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		a.mu.Lock()
		defer a.mu.Unlock()
		if res := r.PostForm.Get("resource"); res != "" {
			a.resource = append(a.resource, res)
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != a.challenge {
				http.Error(w, "PKCE verifier mismatch", http.StatusBadRequest)
				return
			}
			if r.PostForm.Get("code") != a.code {
				http.Error(w, "bad code", http.StatusBadRequest)
				return
			}
		case "refresh_token":
			if !a.refreshOK[r.PostForm.Get("refresh_token")] {
				http.Error(w, "bad refresh token", http.StatusBadRequest)
				return
			}
			a.refreshes++
		default:
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		a.accessSeq++
		tok := fmt.Sprintf("access-%d", a.accessSeq)
		a.valid[tok] = true
		a.refreshOK[fmt.Sprintf("refresh-%d", a.accessSeq)] = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  tok,
			"token_type":    "Bearer",
			"refresh_token": fmt.Sprintf("refresh-%d", a.accessSeq),
			"expires_in":    1, // inside oauth2's expiry delta: next use refreshes
		})
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

// protectedRS is a recording MCP resource server: RFC 9728 metadata, 401 with
// resource_metadata until a currently-valid bearer arrives, and every
// Authorization value it ever sees is recorded.
type protectedRS struct {
	srv *httptest.Server
	as  *fakeAS

	mu   sync.Mutex
	seen []string
}

func newProtectedRS(t *testing.T, as *fakeAS) *protectedRS {
	t.Helper()
	rs := &protectedRS{as: as}
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "fake-cal", Version: "0"}, nil)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv }, nil)
	mux := http.NewServeMux()
	var meta http.Handler
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		meta.ServeHTTP(w, r)
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		rs.mu.Lock()
		rs.seen = append(rs.seen, got)
		rs.mu.Unlock()
		tok := strings.TrimPrefix(got, "Bearer ")
		as.mu.Lock()
		ok := as.valid[tok]
		as.mu.Unlock()
		if !ok {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf("Bearer resource_metadata=%q", rs.srv.URL+"/.well-known/oauth-protected-resource/mcp"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	})
	rs.srv = httptest.NewServer(mux)
	t.Cleanup(rs.srv.Close)
	meta = auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:             rs.srv.URL + "/mcp",
		AuthorizationServers: []string{as.srv.URL},
	})
	return rs
}

func (rs *protectedRS) sawExactly(pred func(string) bool) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, s := range rs.seen {
		if !pred(s) {
			return false
		}
	}
	return len(rs.seen) > 0
}

func oauthEnv(t *testing.T, as *fakeAS) (*Manager, store.Store, *core.Keyring, store.Integration, *Connector) {
	t.Helper()
	rsrv := newProtectedRS(t, as)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	acct, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "cal", Transport: "streamable-http",
		Endpoint: rsrv.srv.URL + "/mcp", AuthKind: "oauth",
	})
	if err != nil {
		t.Fatal(err)
	}
	conn := &Connector{}
	m := &Manager{Store: st, PingEvery: -1}
	// LIFO: this runs BEFORE the servers' Close, releasing the standalone SSE
	// stream so httptest.Server.Close can finish.
	t.Cleanup(func() { _ = m.Disconnect(context.Background(), in.ID) })
	testRS[t.Name()] = rsrv
	return m, st, kr, in, conn
}

var testRS = map[string]*protectedRS{}

// browse follows the authorization hand-off exactly like the owner's browser:
// GET the AS URL, then GET the callback redirect it returns.
func browse(t *testing.T, authURL string) {
	t.Helper()
	nofollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := nofollow.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb := resp.Header.Get("Location")
	if cb == "" {
		t.Fatal("AS did not redirect")
	}
	cbResp, err := http.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	cbResp.Body.Close()
}

func TestOAuthCodeFlowSealsTokensAndRefreshRotates(t *testing.T) {
	as := newFakeAS(t)
	m, st, kr, in, conn := oauthEnv(t, as)
	ctx := context.Background()

	// RedirectURL points at a tiny portal-callback stand-in delivering to the
	// connector — the same wiring MountIntegrationPages provides.
	cbMux := http.NewServeMux()
	cbMux.HandleFunc("GET /oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		conn.Deliver(q.Get("integration"), auth.AuthorizationResult{
			Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss"),
		})
	})
	cbSrv := httptest.NewServer(cbMux)
	defer cbSrv.Close()

	m.OAuthFor = func(row store.Integration) (auth.OAuthHandler, error) {
		return NewOAuthHandler(row.ID, OAuthSetup{
			Store: st, Keyring: kr,
			RedirectURL:   cbSrv.URL + "/oauth/callback?integration=" + row.ID,
			Preregistered: &oauthex.ClientCredentials{ClientID: "hdtp", ClientSecretAuth: &oauthex.ClientSecretAuth{ClientSecret: "s3cret"}},
			Fetch:         conn.Fetcher(row.ID),
		})
	}

	done := make(chan error, 1)
	go func() { done <- m.Connect(ctx, in.ID) }()
	authURL, err := conn.AuthorizeURL(ctx, in.ID, 10*time.Second)
	if err != nil {
		select {
		case cerr := <-done:
			t.Fatalf("connect finished early: %v (no auth URL: %v)", cerr, err)
		default:
			t.Fatal(err)
		}
	}
	browse(t, authURL)
	if err := <-done; err != nil {
		t.Fatalf("connect: %v", err)
	}

	// tokens landed sealed: ciphertext in the row, plaintext only via keyring
	sealed, err := st.GetIntegrationSecret(ctx, in.ID)
	if err != nil || len(sealed) == 0 {
		t.Fatalf("no sealed secret: %v", err)
	}
	if strings.Contains(string(sealed), "access-") {
		t.Fatal("token stored in plaintext")
	}
	tok, err := storedToken(st, kr, in.ID)
	if err != nil || tok == nil || !strings.HasPrefix(tok.AccessToken, "access-") {
		t.Fatalf("unsealed token: %+v %v", tok, err)
	}

	// PKCE + RFC 8707 resource were on the wire
	as.mu.Lock()
	if as.challenge == "" || len(as.resource) < 2 {
		t.Fatalf("challenge=%q resource=%v", as.challenge, as.resource)
	}
	as.mu.Unlock()

	// refresh rotates: expires_in=1 means the next upstream call must refresh
	if err := m.HealthCheck(ctx, in.ID); err != nil {
		t.Fatalf("health: %v", err)
	}
	as.mu.Lock()
	refreshes := as.refreshes
	as.mu.Unlock()
	if refreshes == 0 {
		t.Fatal("no refresh happened")
	}
	tok2, err := storedToken(st, kr, in.ID)
	if err != nil || tok2.AccessToken == tok.AccessToken || tok2.RefreshToken == tok.RefreshToken {
		t.Fatalf("rotation not persisted: %+v vs %+v (%v)", tok2, tok, err)
	}

	// the upstream saw ONLY AS-minted bearers — never anything caller-supplied
	rs := testRS[t.Name()]
	if !rs.sawExactly(func(h string) bool { return h == "" || strings.HasPrefix(h, "Bearer access-") }) {
		t.Fatalf("upstream saw a foreign credential: %v", rs.seen)
	}

	// A restart must not send the owner back to the sign-in page. A fresh
	// handler over the same store resumes from the sealed token AND config:
	// the stored token has expired (expires_in=1), so a resume that could not
	// refresh would 401 and ask for a browser — the fetcher below fails the
	// test if that happens.
	_ = m.Disconnect(ctx, in.ID)
	m.OAuthFor = func(row store.Integration) (auth.OAuthHandler, error) {
		return NewOAuthHandler(row.ID, OAuthSetup{
			Store: st, Keyring: kr,
			RedirectURL:   cbSrv.URL + "/oauth/callback?integration=" + row.ID,
			Preregistered: &oauthex.ClientCredentials{ClientID: "hdtp", ClientSecretAuth: &oauthex.ClientSecretAuth{ClientSecret: "s3cret"}},
			Fetch: func(context.Context, *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
				t.Error("a resumed handler sent the owner to sign in again")
				return nil, fmt.Errorf("no browser after a restart")
			},
		})
	}
	as.mu.Lock()
	before := as.refreshes
	as.mu.Unlock()
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatalf("connect after restart: %v", err)
	}
	as.mu.Lock()
	after := as.refreshes
	as.mu.Unlock()
	if after <= before {
		t.Fatal("the resumed handler did not refresh from the stored config")
	}
	tok3, err := storedToken(st, kr, in.ID)
	if err != nil || tok3 == nil || tok3.AccessToken == tok2.AccessToken {
		t.Fatalf("the refreshed token after restart was not persisted: %+v %v", tok3, err)
	}
}

// storedToken reads the sealed token the way a resumed handler does (openStored).
func storedToken(st store.Store, kr Sealer, integrationID string) (*oauth2.Token, error) {
	blob, err := openStored(st, kr, integrationID)
	if err != nil || blob == nil {
		return nil, err
	}
	return blob.Token, nil
}

func TestOAuthIssMismatchAborts(t *testing.T) {
	as := newFakeAS(t)
	as.issOverride = "https://evil.example"
	m, st, kr, in, conn := oauthEnv(t, as)
	ctx := context.Background()

	m.OAuthFor = func(row store.Integration) (auth.OAuthHandler, error) {
		return NewOAuthHandler(row.ID, OAuthSetup{
			Store: st, Keyring: kr,
			RedirectURL:   "http://127.0.0.1:1/callback", // never reached: browse() parses the redirect
			Preregistered: &oauthex.ClientCredentials{ClientID: "hdtp", ClientSecretAuth: &oauthex.ClientSecretAuth{ClientSecret: "s3cret"}},
			Fetch: func(fctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
				nofollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				resp, err := nofollow.Get(args.URL)
				if err != nil {
					return nil, err
				}
				resp.Body.Close()
				loc, err := resp.Location()
				if err != nil {
					return nil, err
				}
				q := loc.Query()
				return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
			},
		})
	}
	_ = conn
	err := m.Connect(ctx, in.ID)
	if err == nil {
		t.Fatal("iss mismatch accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "iss") {
		t.Fatalf("aborted for the wrong reason: %v", err)
	}
	if sealed, _ := st.GetIntegrationSecret(ctx, in.ID); len(sealed) != 0 {
		t.Fatal("tokens sealed despite aborted flow")
	}
	// an aborted authorization is an AUTH failure, not an outage (SPEC §6.3)
	row, _ := st.GetIntegrationByID(ctx, in.ID)
	if row.Status != "auth_error" {
		t.Fatalf("status after abort: %s", row.Status)
	}
}

func TestOAuthHandlerNeedsAClient(t *testing.T) {
	if _, err := NewOAuthHandler("x", OAuthSetup{}); err == nil {
		t.Fatal("handler built with no client registration method")
	}
}

// AC (P10-04g): a static credential round-trips sealed, and an integration with
// none set is a configuration state rather than an error (SPEC §6.3, §11.3).
func TestStaticCredentialRoundTripsSealed(t *testing.T) {
	st, err0 := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err0 != nil {
		t.Fatal(err0)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	kr, kerr := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if kerr != nil {
		t.Fatal(kerr)
	}
	ctx := context.Background()
	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "cf", Transport: "streamable-http",
		Endpoint: "https://api.invalid", AuthKind: "static", Status: "disabled",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unset is not a failure: the owner simply has not supplied it yet.
	if h, v, err := OpenStatic(st, kr, in.ID); err != nil || h != "" || v != "" {
		t.Fatalf("unset credential read as %q/%q err=%v", h, v, err)
	}
	if err := SealStatic(st, kr, in.ID, "Authorization", "Bearer s3cret"); err != nil {
		t.Fatal(err)
	}
	h, v, err := OpenStatic(st, kr, in.ID)
	if err != nil || h != "Authorization" || v != "Bearer s3cret" {
		t.Fatalf("round trip: %q %q %v", h, v, err)
	}

	// The stored bytes must not contain the secret: a copy of the database
	// alone cannot use the credential (§3.7, §11.3).
	sealed, err := st.GetIntegrationSecret(ctx, in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("s3cret")) {
		t.Fatal("the credential is stored in the clear")
	}
	// A credential sealed for one integration must not open under another's AAD.
	other, _ := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "other", Transport: "streamable-http",
		Endpoint: "https://api.invalid", AuthKind: "static", Status: "disabled",
	})
	if err := st.SetIntegrationSecret(ctx, other.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStatic(st, kr, other.ID); err == nil {
		t.Fatal("a credential moved between integrations still opened")
	}

	// Both halves are required.
	if err := SealStatic(st, kr, in.ID, "", "x"); err == nil {
		t.Fatal("a credential with no header was accepted")
	}
}

// testSettingsAAD is the settings table's AAD (core.SettingsAAD). The credential lives in
// the settings table, whose one decrypting reader opens every secret row with
// this value — sealing it under anything else fails STARTUP, not the read.
var testSettingsAAD = core.SettingsAAD()

// AC (P10-04h): the pre-registered OAuth client round-trips sealed, and an
// integration with none registered is reported rather than left to time out.
func TestOAuthClientRoundTripsSealed(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	kr, err := core.OpenKeyring(filepath.Join(t.TempDir(), "master.key"), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	acct, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "gcal", Transport: "streamable-http",
		Endpoint: "https://api.invalid", AuthKind: "oauth", Status: "disabled",
	})
	if err != nil {
		t.Fatal(err)
	}

	// None registered is a configuration state, not an error.
	if pre, err := OpenClient(st, kr, testSettingsAAD, in.ID); err != nil || pre != nil {
		t.Fatalf("unregistered client read as %+v %v", pre, err)
	}
	if err := SealClient(st, kr, testSettingsAAD, in.ID, "cid-123", "csecret"); err != nil {
		t.Fatal(err)
	}
	pre, err := OpenClient(st, kr, testSettingsAAD, in.ID)
	if err != nil || pre == nil || pre.ClientID != "cid-123" {
		t.Fatalf("round trip: %+v %v", pre, err)
	}
	if pre.ClientSecretAuth == nil || pre.ClientSecretAuth.ClientSecret != "csecret" {
		t.Fatalf("client secret lost: %+v", pre.ClientSecretAuth)
	}

	// A public client — no secret — is legitimate and must not carry an empty
	// secret auth, which a provider would reject.
	if err := SealClient(st, kr, testSettingsAAD, in.ID, "public-1", ""); err != nil {
		t.Fatal(err)
	}
	pub, err := OpenClient(st, kr, testSettingsAAD, in.ID)
	if err != nil || pub.ClientSecretAuth != nil {
		t.Fatalf("public client carried secret auth: %+v %v", pub, err)
	}

	// The secret is never at rest in the clear.
	rows, _ := st.ListSettings(ctx)
	for _, r := range rows {
		if strings.Contains(r.Value, "csecret") {
			t.Fatalf("the client secret is stored in the clear under %q", r.Key)
		}
	}
	if err := SealClient(st, kr, testSettingsAAD, in.ID, "", "x"); err == nil {
		t.Fatal("a client with no id was accepted")
	}
}

// The owner's authorize tab must survive newer flows. States were evicted
// "one pending flow per integration", and with a dead token the background
// connect retry mints a flow every attempt — so the state the owner's tab
// carried was gone before they finished signing in, and every completed
// authorization answered "no authorization is pending for this callback".
func TestPendingStatesOutliveNewerFlows(t *testing.T) {
	c := &Connector{}
	c.rememberState("integ-1", "https://as.example/authorize?state=first")
	c.rememberState("integ-1", "https://as.example/authorize?state=second") // background retry
	c.rememberState("integ-2", "https://as.example/authorize?state=other")

	for _, tc := range []struct{ state, want string }{
		{"first", "integ-1"}, // the owner's tab, started before the retry
		{"second", "integ-1"},
		{"other", "integ-2"},
	} {
		if id, ok := c.IntegrationForState(tc.state); !ok || id != tc.want {
			t.Fatalf("state %q -> %q,%v; want %q", tc.state, id, ok, tc.want)
		}
	}
	if _, ok := c.IntegrationForState(""); ok {
		t.Fatal("the empty state resolved")
	}

	// Expiry, not eviction, is what bounds the map.
	c.mu.Lock()
	e := c.states["first"]
	e.expires = time.Now().Add(-time.Minute)
	c.states["first"] = e
	c.mu.Unlock()
	if _, ok := c.IntegrationForState("first"); ok {
		t.Fatal("an expired state resolved")
	}
	c.mu.Lock()
	_, still := c.states["first"]
	n := len(c.states)
	c.mu.Unlock()
	if still || n != 2 {
		t.Fatalf("expired state not pruned: present=%v len=%d", still, n)
	}
}

// Dynamic registration's minted client is captured off the wire (the SDK keeps
// the RFC 7591 response to itself) and handed to OnRegistered, with the body
// restored for the SDK to read.
func TestRegistrationCaptureObservesTheMintedClient(t *testing.T) {
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/register":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"client_id":"cid-123","client_secret":"sec-456","token_endpoint_auth_method":"none"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			// A 200 token response must NOT be mistaken for a registration.
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"bearer","client_id":"never-this"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer as.Close()

	var gotID, gotSecret string
	rc := &registrationCapture{next: http.DefaultTransport, onRegistered: func(id, secret string) { gotID, gotSecret = id, secret }}
	client := &http.Client{Transport: rc}

	res, err := client.Post(as.URL+"/register", "application/json", strings.NewReader(`{"client_name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), "cid-123") {
		t.Fatalf("the SDK's view of the body was consumed: %s", body)
	}
	if gotID != "cid-123" || gotSecret != "sec-456" {
		t.Fatalf("captured %q/%q", gotID, gotSecret)
	}

	gotID = ""
	if _, err := client.Post(as.URL+"/token", "application/json", strings.NewReader(`{}`)); err != nil {
		t.Fatal(err)
	}
	if gotID != "" {
		t.Fatal("a token response was captured as a registration")
	}
}

package integrations

// Upstream OAuth (SPEC §6.3): the SDK's AuthorizationCodeHandler carries the MCP
// auth spec 2026-07-28 — RFC 9728 discovery, RFC 8414/OIDC metadata, PKCE S256,
// RFC 8707 resource, RFC 9207 iss validation — and this file wires it to the
// node: Client ID Metadata Documents preferred over (deprecated) DCR, tokens
// keyring-sealed into the integration row the moment they are minted or
// refreshed, and a browser hand-off seam the portal Connect flow drives. A
// caller's token NEVER rides upstream: nothing here ever reads caller identity.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// Sealer is the keyring slice this file needs (core.Keyring satisfies it).
type Sealer interface {
	Encrypt(plaintext, aad []byte) ([]byte, error)
	Decrypt(sealed, aad []byte) ([]byte, error)
}

func secretAAD(integrationID string) []byte {
	return []byte("integration-secret:" + integrationID)
}

// storedOAuth is the sealed blob of an `auth: oauth` integration: the token
// and the parts of the oauth2 config a refresh needs. Both persist, so a
// restarted node resumes with the SAME client and token — a client registered
// dynamically is not on file anywhere else, and a token issued to it is only
// refreshable by it. Without the config, every restart meant a new
// registration and a new sign-in by the owner.
type storedOAuth struct {
	Token        *oauth2.Token `json:"token"`
	ClientID     string        `json:"client_id,omitempty"`
	ClientSecret string        `json:"client_secret,omitempty"`
	AuthURL      string        `json:"auth_url,omitempty"`
	TokenURL     string        `json:"token_url,omitempty"`
	AuthStyle    int           `json:"auth_style,omitempty"`
	Scopes       []string      `json:"scopes,omitempty"`
}

func (o *storedOAuth) config() *oauth2.Config {
	if o.TokenURL == "" || o.ClientID == "" {
		return nil
	}
	return &oauth2.Config{
		ClientID: o.ClientID, ClientSecret: o.ClientSecret, Scopes: o.Scopes,
		Endpoint: oauth2.Endpoint{AuthURL: o.AuthURL, TokenURL: o.TokenURL, AuthStyle: oauth2.AuthStyle(o.AuthStyle)},
	}
}

// SealToken persists an OAuth token encrypted under the keyring master key.
// Without a config the token cannot be refreshed after a restart; SealOAuth is
// what the handler uses once it has one.
func SealToken(st store.Store, kr Sealer, integrationID string, tok *oauth2.Token) error {
	return SealOAuth(st, kr, integrationID, tok, nil)
}

// SealOAuth persists the token with the config that can refresh it.
func SealOAuth(st store.Store, kr Sealer, integrationID string, tok *oauth2.Token, oc *oauth2.Config) error {
	blob := storedOAuth{Token: tok}
	if oc != nil {
		blob.ClientID, blob.ClientSecret, blob.Scopes = oc.ClientID, oc.ClientSecret, oc.Scopes
		blob.AuthURL, blob.TokenURL, blob.AuthStyle = oc.Endpoint.AuthURL, oc.Endpoint.TokenURL, int(oc.Endpoint.AuthStyle)
	}
	plain, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("integrations: %w", err)
	}
	sealed, err := kr.Encrypt(plain, secretAAD(integrationID))
	if err != nil {
		return err
	}
	return st.SetIntegrationSecret(context.Background(), integrationID, sealed)
}

// openStored loads and unseals what is on file (nil when nothing is). A blob
// written before the config travelled with the token is a bare oauth2.Token
// and still opens — as a token with nothing to refresh it.
func openStored(st store.Store, kr Sealer, integrationID string) (*storedOAuth, error) {
	sealed, err := st.GetIntegrationSecret(context.Background(), integrationID)
	if err != nil || len(sealed) == 0 {
		return nil, err
	}
	plain, err := kr.Decrypt(sealed, secretAAD(integrationID))
	if err != nil {
		return nil, err
	}
	var blob storedOAuth
	if err := json.Unmarshal(plain, &blob); err != nil {
		return nil, fmt.Errorf("integrations: %w", err)
	}
	if blob.Token == nil {
		var legacy oauth2.Token
		if err := json.Unmarshal(plain, &legacy); err != nil || legacy.AccessToken == "" {
			return nil, nil
		}
		blob.Token = &legacy
	}
	return &blob, nil
}

// OpenToken loads and unseals the stored token (nil when none is stored).
func OpenToken(st store.Store, kr Sealer, integrationID string) (*oauth2.Token, error) {
	blob, err := openStored(st, kr, integrationID)
	if err != nil || blob == nil {
		return nil, err
	}
	return blob.Token, nil
}

// persistingSource wraps a TokenSource and seals every newly minted token —
// this is where refresh rotation lands in the store.
type persistingSource struct {
	inner         oauth2.TokenSource
	st            store.Store
	kr            Sealer
	integrationID string
	cfg           *oauth2.Config

	mu   sync.Mutex
	last string // last persisted access token, to avoid rewrites
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	tok, err := p.inner.Token()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	changed := tok.AccessToken != p.last
	if changed {
		p.last = tok.AccessToken
	}
	p.mu.Unlock()
	if changed {
		if err := SealOAuth(p.st, p.kr, p.integrationID, tok, p.cfg); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

// resumable is the stored token a handler can start from, or nil: nothing on
// file, nothing to read it with, or an empty token.
func resumable(s OAuthSetup, integrationID string) (*storedOAuth, error) {
	if s.Store == nil || s.Keyring == nil {
		return nil, nil
	}
	stored, err := openStored(s.Store, s.Keyring, integrationID)
	if err != nil || stored == nil || stored.Token == nil || stored.Token.AccessToken == "" {
		return nil, err
	}
	return stored, nil
}

// OAuthSetup is what NewOAuthHandler needs beyond the integration row.
type OAuthSetup struct {
	Store   store.Store
	Keyring Sealer
	// RedirectURL is the portal callback route. It carries nothing that names
	// the integration: it must match, byte for byte, what was registered with
	// the provider, so the callback finds its flow by the OAuth state instead.
	RedirectURL string
	// ClientIDMetadataURL configures a Client ID Metadata Document (preferred).
	ClientIDMetadataURL string
	// Preregistered is the fallback when no CIMD is hosted.
	Preregistered *oauthex.ClientCredentials
	// DynamicRegistration is the last resort SPEC §6.3 keeps: RFC 7591 metadata
	// the node registers itself with when the provider offers a registration
	// endpoint and nothing better is configured. Nil disables it.
	DynamicRegistration *oauthex.ClientRegistrationMetadata
	// Fetch hands the authorization URL to the owner's browser and returns the
	// callback's code/state/iss (the portal Connect flow, SPEC §6.3).
	Fetch auth.AuthorizationCodeFetcher
	// HTTPClient serves discovery/registration/exchange/refresh requests.
	HTTPClient *http.Client
	// OnRegistered observes the client dynamic registration mints. The SDK
	// keeps the RFC 7591 response to itself, so the only place the credentials
	// pass in the clear is the HTTP exchange — the transport below captures
	// them there. Persisting the client means the NEXT authorization runs as a
	// preregistered client instead of minting yet another registration at the
	// provider on every full auth flow.
	OnRegistered func(clientID, clientSecret string)
}

// NewOAuthHandler builds the code-flow handler for one integration. Client
// identity follows SPEC §6.3's order: a Client ID Metadata Document, else a
// pre-registered client, else — deprecated but kept as the last resort — RFC
// 7591 dynamic registration. The SDK tries them in that order per provider.
func NewOAuthHandler(integrationID string, s OAuthSetup) (auth.OAuthHandler, error) {
	if s.DynamicRegistration != nil && s.OnRegistered != nil && s.HTTPClient != nil {
		base := s.HTTPClient.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		client := *s.HTTPClient // the shared client must not grow the capture
		client.Transport = &registrationCapture{next: base, onRegistered: s.OnRegistered}
		s.HTTPClient = &client
	}
	cfg := &auth.AuthorizationCodeHandlerConfig{
		RedirectURL:              s.RedirectURL,
		AuthorizationCodeFetcher: s.Fetch,
		RequestRefreshToken:      true,
		Client:                   s.HTTPClient,
		NewTokenSource: func(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
			if err := SealOAuth(s.Store, s.Keyring, integrationID, tok, oc); err != nil {
				return nil, err
			}
			return &persistingSource{
				inner: oc.TokenSource(ctx, tok), st: s.Store, kr: s.Keyring,
				integrationID: integrationID, last: tok.AccessToken, cfg: oc,
			}, nil
		},
	}
	// Resume from what is on file: a stored token is the initial source, so a
	// restart neither registers a new client nor sends the owner to sign in.
	// With its config it refreshes itself; without (an older blob) it serves
	// until it expires, and the 401 then starts an ordinary authorization.
	if stored, err := resumable(s, integrationID); err == nil && stored != nil {
		var inner oauth2.TokenSource = oauth2.StaticTokenSource(stored.Token)
		oc := stored.config()
		if oc != nil {
			rctx := context.Background()
			if s.HTTPClient != nil {
				rctx = context.WithValue(rctx, oauth2.HTTPClient, s.HTTPClient)
			}
			inner = oc.TokenSource(rctx, stored.Token)
		}
		cfg.InitialTokenSource = &persistingSource{
			inner: inner, st: s.Store, kr: s.Keyring,
			integrationID: integrationID, last: stored.Token.AccessToken, cfg: oc,
		}
	}
	if s.ClientIDMetadataURL != "" {
		cfg.ClientIDMetadataDocumentConfig = &auth.ClientIDMetadataDocumentConfig{URL: s.ClientIDMetadataURL}
	}
	if s.Preregistered != nil {
		cfg.PreregisteredClient = s.Preregistered
	}
	if s.DynamicRegistration != nil {
		cfg.DynamicClientRegistrationConfig = &auth.DynamicClientRegistrationConfig{Metadata: s.DynamicRegistration}
	}
	if cfg.ClientIDMetadataDocumentConfig == nil && cfg.PreregisteredClient == nil && cfg.DynamicClientRegistrationConfig == nil {
		return nil, fmt.Errorf("integrations: oauth needs a client id metadata URL, a preregistered client, or dynamic registration")
	}
	return auth.NewAuthorizationCodeHandler(cfg)
}

// ConnectFlow is one in-flight browser authorization: the handler publishes the
// AS URL, the portal redirects the owner there, and the callback route delivers
// the result. Buffered so neither side can wedge the other.
type ConnectFlow struct {
	URL    chan string
	Result chan auth.AuthorizationResult
	Err    chan error
}

// Connector tracks in-flight portal Connect flows by integration id.
type Connector struct {
	mu      sync.Mutex
	flows   map[string]*ConnectFlow
	origins map[string]string
	states  map[string]stateEntry // OAuth state → the flow it belongs to
}

// stateEntry keeps one pending authorization's identity until it expires.
// States used to be evicted "one pending flow per integration" — but with a
// dead token the background connect retry mints a fresh flow every attempt,
// so the state the OWNER'S TAB was carrying got evicted before they could
// finish signing in, and every completed authorization came back "no
// authorization is pending for this callback". A state is now valid for its
// own lifetime, several may wait at once, and expiry is what bounds the map.
type stateEntry struct {
	id      string
	expires time.Time
}

// stateTTL is how long an authorize tab may sit before its callback is stale —
// generous, because a person signing in to a provider can take a while.
const stateTTL = 15 * time.Minute

// IntegrationForState names the integration whose authorization carried this
// state. The callback route has no other way to tell flows apart: the redirect
// URI registered with the provider must be used verbatim, so it cannot carry
// the integration id, and state is the one value OAuth guarantees comes back.
func (c *Connector) IntegrationForState(state string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneStatesLocked()
	e, ok := c.states[state]
	return e.id, ok && state != ""
}

func (c *Connector) pruneStatesLocked() {
	now := time.Now()
	for k, e := range c.states {
		if now.After(e.expires) {
			delete(c.states, k)
		}
	}
}

func (c *Connector) rememberState(integrationID, authorizeURL string) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return
	}
	state := u.Query().Get("state")
	if state == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.states == nil {
		c.states = map[string]stateEntry{}
	}
	c.pruneStatesLocked()
	c.states[state] = stateEntry{id: integrationID, expires: time.Now().Add(stateTTL)}
}

// SetOrigin remembers the scheme://host the owner's browser used to reach the
// portal, so the OAuth redirect URI registered with the provider is one that
// browser can actually come back to. A node bound to 127.0.0.1:8080 inside a
// container is reached by its owner on localhost:18120; a callback built from
// the bind address would land nowhere.
func (c *Connector) SetOrigin(integrationID, origin string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.origins == nil {
		c.origins = map[string]string{}
	}
	c.origins[integrationID] = origin
}

// Origin returns the remembered browser origin, or "".
func (c *Connector) Origin(integrationID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.origins[integrationID]
}

// Fail tells a waiting portal request that the flow will not produce a URL —
// the handler could not even be built, say. Without it the owner waited out a
// timeout and read a message that named no cause.
func (c *Connector) Fail(integrationID string, err error) {
	f := c.flow(integrationID)
	select {
	case f.Err <- err:
	default:
		select {
		case <-f.Err:
		default:
		}
		f.Err <- err
	}
}

func (c *Connector) flow(integrationID string) *ConnectFlow {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.flows == nil {
		c.flows = map[string]*ConnectFlow{}
	}
	f := c.flows[integrationID]
	if f == nil {
		f = &ConnectFlow{
			URL:    make(chan string, 1),
			Result: make(chan auth.AuthorizationResult, 1),
			Err:    make(chan error, 1),
		}
		c.flows[integrationID] = f
	}
	return f
}

// Fetcher is the AuthorizationCodeFetcher for one integration: it hands the URL
// to the waiting portal request and blocks until the callback (or ctx) ends.
func (c *Connector) Fetcher(integrationID string) auth.AuthorizationCodeFetcher {
	return func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		f := c.flow(integrationID)
		c.rememberState(integrationID, args.URL)
		select {
		case f.URL <- args.URL:
		default: // a stale unread URL is replaced
			select {
			case <-f.URL:
			default:
			}
			f.URL <- args.URL
		}
		select {
		case res := <-f.Result:
			return &res, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// AuthorizeURL blocks until the handler publishes the AS URL (portal redirect).
func (c *Connector) AuthorizeURL(ctx context.Context, integrationID string, timeout time.Duration) (string, error) {
	f := c.flow(integrationID)
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case u := <-f.URL:
		return u, nil
	case err := <-f.Err:
		return "", err
	case <-t.C:
		return "", fmt.Errorf("integrations: no authorization URL within %v", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Deliver completes the flow from the portal callback route. The NEWEST
// result always wins: a stale unread one is replaced, never the other way.
func (c *Connector) Deliver(integrationID string, res auth.AuthorizationResult) {
	f := c.flow(integrationID)
	c.mu.Lock()
	delete(c.states, res.State)
	c.mu.Unlock()
	for {
		select {
		case f.Result <- res:
			return
		default:
			select {
			case <-f.Result: // drop the stale one and retry
			default:
			}
		}
	}
}

/* --------------------- static credentials (SPEC §6.3) --------------------- */

// staticCred is what an `auth: static` integration stores, sealed. It is a
// header name and value because that is the only shape §6.3 promises to attach:
// anything richer would be a second, undocumented auth mechanism.
type staticCred struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

// SealStatic stores a static credential under the keyring, so a copy of the
// database alone cannot use it (SPEC §3.7, §11.3).
func SealStatic(st store.Store, kr Sealer, integrationID, header, value string) error {
	if header == "" || value == "" {
		return fmt.Errorf("integrations: a static credential needs a header and a value")
	}
	plain, err := json.Marshal(staticCred{Header: header, Value: value})
	if err != nil {
		return fmt.Errorf("integrations: %w", err)
	}
	sealed, err := kr.Encrypt(plain, secretAAD(integrationID))
	if err != nil {
		return fmt.Errorf("integrations: %w", err)
	}
	return st.SetIntegrationSecret(context.Background(), integrationID, sealed)
}

// OpenStatic reads a stored static credential. It returns empty strings with a
// nil error when none is set — an integration whose credential the owner has not
// supplied yet is a configuration state, not a failure.
func OpenStatic(st store.Store, kr Sealer, integrationID string) (header, value string, err error) {
	sealed, err := st.GetIntegrationSecret(context.Background(), integrationID)
	if err != nil || len(sealed) == 0 {
		return "", "", err
	}
	plain, err := kr.Decrypt(sealed, secretAAD(integrationID))
	if err != nil {
		return "", "", fmt.Errorf("integrations: static credential: %w", err)
	}
	var c staticCred
	if err := json.Unmarshal(plain, &c); err != nil {
		return "", "", fmt.Errorf("integrations: static credential: %w", err)
	}
	return c.Header, c.Value, nil
}

/* ------------------ OAuth client identity (SPEC §6.3, E4) ------------------ */

// clientKey names where an integration's OAuth client credentials live. They
// cannot share the integration-secret slot: that slot holds the ACCESS token,
// and an integration needs both at once.
func clientKey(integrationID string) string {
	return "integration." + integrationID + ".oauth_client_secret"
}

type clientCred struct {
	// Integration binds the credential to the row it was registered for.
	//
	// The ciphertext lives in the `settings` table, and that table's ONE
	// decrypting reader opens every secret row with the settings AAD. Sealing
	// this one under a per-integration AAD therefore made that reader fail — and
	// it fails startup, so registering an OAuth client through the portal left
	// the node permanently unable to boot, blaming the keyring for a row the
	// owner had just written. The binding moves inside the plaintext instead,
	// where it is checked on read: a row copied between integrations still
	// opens, and is still refused.
	Integration string `json:"integration_id"`
	ID          string `json:"client_id"`
	Secret      string `json:"client_secret"`
}

// SealClient stores a pre-registered OAuth client for one integration.
//
// SPEC §6.3 prefers a Client ID Metadata Document, "else pre-registered client
// ID". A CIMD must be published at a stable public HTTPS URL, and a node behind
// NAT or on loopback has none — and publishing one
// would be a new outward-facing surface on a node whose design avoids them. So
// pre-registration is what this implements (escalation E4, option A).
// settingsAAD must match the AAD the settings table's reader uses, because that
// reader opens every secret row there. It is passed in rather than duplicated so
// the two cannot drift into the boot failure described on clientCred.
func SealClient(st store.Store, kr Sealer, settingsAAD []byte, integrationID, clientID, clientSecret string) error {
	if clientID == "" {
		return fmt.Errorf("integrations: an OAuth client needs a client id")
	}
	plain, err := json.Marshal(clientCred{Integration: integrationID, ID: clientID, Secret: clientSecret})
	if err != nil {
		return err
	}
	sealed, err := kr.Encrypt(plain, settingsAAD)
	if err != nil {
		return err
	}
	return st.PutSetting(context.Background(), store.Setting{
		Key: clientKey(integrationID), Value: base64.StdEncoding.EncodeToString(sealed), Secret: true,
	})
}

// OpenClient reads a stored OAuth client, or nil when none is registered.
func OpenClient(st store.Store, kr Sealer, settingsAAD []byte, integrationID string) (*oauthex.ClientCredentials, error) {
	rows, err := st.ListSettings(context.Background())
	if err != nil {
		return nil, err
	}
	raw := ""
	for _, r := range rows {
		if r.Key == clientKey(integrationID) {
			raw = r.Value
		}
	}
	if raw == "" {
		return nil, nil // no client registered yet: a configuration state
	}
	sealed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("integrations: oauth client: %w", err)
	}
	plain, err := kr.Decrypt(sealed, settingsAAD)
	if err != nil {
		return nil, fmt.Errorf("integrations: oauth client: %w", err)
	}
	var c clientCred
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, fmt.Errorf("integrations: oauth client: %w", err)
	}
	// The AAD binds this to the settings table, not to a row, so the row it was
	// written for is checked here: a credential moved between integrations opens
	// and is then refused, rather than being used for the wrong provider.
	if c.Integration != "" && c.Integration != integrationID {
		return nil, fmt.Errorf("integrations: oauth client was registered for a different integration")
	}
	cc := &oauthex.ClientCredentials{ClientID: c.ID}
	if c.Secret != "" {
		cc.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: c.Secret}
	}
	return cc, nil
}

// registrationCapture watches the OAuth HTTP exchanges for the one that mints
// a dynamic client — RFC 7591: a POST answered 201 with a client_id — and
// hands the credentials to OnRegistered. The body is restored for the SDK,
// which remains the flow's only driver.
type registrationCapture struct {
	next         http.RoundTripper
	onRegistered func(clientID, clientSecret string)
}

func (rc *registrationCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rc.next.RoundTrip(req)
	if err != nil || req.Method != http.MethodPost || res.StatusCode != http.StatusCreated {
		return res, err
	}
	body, rerr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(body))
	if rerr != nil {
		return res, nil
	}
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if json.Unmarshal(body, &reg) == nil && reg.ClientID != "" {
		rc.onRegistered(reg.ClientID, reg.ClientSecret)
	}
	return res, nil
}

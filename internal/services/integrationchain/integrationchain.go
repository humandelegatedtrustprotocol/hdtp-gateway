// Package integrationchain is the integrations composition root (SPEC §6).
//
// `serve` used to build `integrations.Manager{Store: st}` — one of thirteen
// fields — and the portal separately constructed its OWN `Cataloger` and
// `Exposures` with every hook nil. So the machinery P3 built and tested ran
// nowhere:
//
//   - a catalog was snapshotted only when an owner clicked "Refresh";
//   - `Exposures.Reconcile`, the §6.5 stale guard, had no caller at all, so the
//     property that section states — "a silently changed upstream can therefore
//     never widen what contacts reach" — was unenforced in the shipped binary;
//   - publishing an exposure set rebuilt nothing and emitted no
//     `tools/list_changed`, and a withheld integration kept its tools listed;
//   - every audit call inside the manager was a no-op.
//
// This file builds ONE chain and hands the same objects to both the node and the
// portal, so there is exactly one view of an integration's state.
package integrationchain

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/integrations"
)

// upstreamTimeout bounds every call this node makes to an upstream MCP server.
// The default http.Client has no timeout at all, so one unresponsive upstream
// could pin a health-cycle goroutine indefinitely.
const upstreamTimeout = 30 * time.Second

// Chain is the wired set. The portal and the node share it.
type Chain struct {
	Manager   *integrations.Manager
	Cataloger *integrations.Cataloger
	Exposures *integrations.Exposures
}

// Build wires the manager, cataloger and exposure set together.
//
// onSurfaceChange is called whenever what contacts may reach has changed — a new
// exposure set, a stale-guard narrowing, a withhold or a restore. It is how
// §6.5 and §6.10's "rebuild per-caller servers and emit tools/list_changed"
// actually happens.
func Build(st store.Store, kr integrations.Sealer,
	connector *integrations.Connector, portalBase string,
	auditFn func(action, resource, outcome string),
	onSurfaceChange func(integrationID string),
	settingValues func(context.Context) (map[string]string, error),
	onAttention func(integrationID string)) *Chain {

	c := &Chain{
		Manager: &integrations.Manager{
			Store:      st,
			Audit:      auditFn,
			HTTPClient: &http.Client{Timeout: upstreamTimeout},
			// §6.3: an `auth: static` integration attaches a sealed header to
			// every upstream request. Nothing supplied this, so a static
			// credential the owner configured was never sent and the upstream
			// answered 401 with no explanation the owner could see.
			StaticHeader: func(in store.Integration) (string, string, error) {
				if kr == nil {
					return "", "", nil
				}
				h, v, err := integrations.OpenStatic(st, kr, in.ID)
				if err != nil {
					auditFn("static_credential", "account:"+in.AccountID+" integration:"+in.Slug, "unreadable")
					return "", "", err
				}
				if h == "" {
					auditFn("static_credential", "account:"+in.AccountID+" integration:"+in.Slug, "unset")
				}
				return h, v, nil
			},
		},
		Exposures: &integrations.Exposures{Store: st, Audit: auditFn, OnChange: onSurfaceChange},
	}

	// §6.2: a supervised child receives EXACTLY the environment the owner
	// configured. `StdioConfigFor` had no production caller, so every child ran
	// with none at all — stdio.go sets `cmd.Env` from the allow-list and never
	// inherits — and there was no way to supply one. That made §12.3's -full
	// image (node and uv, "so supervised stdio children can run in-container")
	// unusable: npx cannot resolve a runtime without PATH, and environment
	// variables are how such servers take their credentials.
	c.Manager.StdioConfigFor = func(in store.Integration) integrations.StdioConfig {
		return integrations.StdioConfig{
			Command: in.Command,
			Env:     stdioEnv(settingValues, in.AccountID, in.Slug, auditFn),
		}
	}

	// §6.3: an `auth: oauth` integration needs a handler, and NewOAuthHandler
	// had only test callers — so the portal's Connect button pushed an
	// authorization URL nobody was waiting for and timed out at 504 every time.
	if kr != nil && connector != nil {
		c.Manager.OAuthFor = func(in store.Integration) (auth.OAuthHandler, error) {
			pre, err := integrations.OpenClient(st, kr, core.SettingsAAD(), in.ID)
			if err != nil {
				return nil, err
			}
			// The callback must be an address the OWNER'S BROWSER can reach: the
			// origin it used to open the portal, when known, not the bind address.
			base := connector.Origin(in.ID)
			if base == "" {
				base = portalBase
			}
			redirect := strings.TrimSuffix(base, "/") + "/oauth/callback"
			setup := integrations.OAuthSetup{
				Store:         st,
				Keyring:       kr,
				RedirectURL:   redirect,
				Preregistered: pre,
				Fetch:         connector.Fetcher(in.ID),
				HTTPClient:    &http.Client{Timeout: upstreamTimeout},
			}
			if pre == nil {
				// No client on file: fall back to registering one with the
				// provider (SPEC §6.3's last resort). A public client with PKCE —
				// the node holds no secret a provider could bind to.
				// How the client was obtained is a fact about this attempt, not
				// its verdict; the connect result is audited on its own.
				auditFn("oauth_connect", "account:"+in.AccountID+" integration:"+in.Slug+" method:dynamic_registration", "started")
				setup.DynamicRegistration = &oauthex.ClientRegistrationMetadata{
					ClientName:              "PACT gateway (" + in.Slug + ")",
					RedirectURIs:            []string{redirect},
					GrantTypes:              []string{"authorization_code", "refresh_token"},
					ResponseTypes:           []string{"code"},
					TokenEndpointAuthMethod: "none",
				}
				// Persist what registration mints, so the NEXT flow runs as a
				// preregistered client instead of registering client after
				// client at the provider on every full authorization.
				setup.OnRegistered = func(clientID, clientSecret string) {
					if err := integrations.SealClient(st, kr, core.SettingsAAD(), in.ID, clientID, clientSecret); err != nil {
						auditFn("oauth_client", "account:"+in.AccountID+" integration:"+in.Slug, "error")
						return
					}
					auditFn("oauth_client", "account:"+in.AccountID+" integration:"+in.Slug+" method:dynamic_registration", "stored")
				}
			}
			return integrations.NewOAuthHandler(in.ID, setup)
		}
	}
	c.Cataloger = &integrations.Cataloger{Store: st, Manager: c.Manager, Audit: auditFn}

	// A new snapshot version runs the §6.5 stale guard: an exposed tool whose
	// upstream definition changed is withdrawn until the owner re-confirms it.
	// Reconcile can only ever NARROW what is served, so running it automatically
	// is safe in the direction that matters.
	c.Cataloger.OnMinted = func(integrationID string) {
		if _, changed, err := c.Exposures.Reconcile(context.Background(), integrationID); err == nil && changed {
			auditFn("exposure_stale_guard", "integration:"+integrationID, "narrowed")
		}
	}

	// §6.4: snapshot on connect, on the periodic health cycle, and when the
	// upstream announces its tool list changed. Refresh mints a new version only
	// when the content hashes actually differ, so the periodic call is cheap and
	// does not churn versions.
	snapshot := func(integrationID string) {
		ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		defer cancel()
		_, _, _ = c.Cataloger.Refresh(ctx, integrationID)
	}
	c.Manager.OnConnected = snapshot
	c.Manager.OnHealthy = snapshot
	c.Manager.OnToolListChanged = snapshot
	c.Manager.OnAuthError = onAttention

	// §6.10: withhold and restore change what `tools/list` may show.
	c.Manager.OnAvailability = func(integrationID string, withheld bool) {
		outcome := "restored"
		if withheld {
			outcome = "withheld"
		}
		auditFn("integration_availability", "integration:"+integrationID, outcome)
		if onSurfaceChange != nil {
			onSurfaceChange(integrationID)
		}
	}
	return c
}

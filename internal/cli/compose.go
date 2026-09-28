package cli

// The serving composition of SPEC §2.2: `serve` builds the public node, starts
// the configured tunnel adapter in front of it, mounts the portal and the owner
// MCP on the internal bind, and shuts all three down in order.
//
// Nothing here decides policy. The knobs were already derived from the adapter
// at config load (SPEC §10.1), the node owns the public surface, and the portal
// pages own their own authorization — this file only puts them together and
// takes them apart again.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/integrations"
	"github.com/pact-cloud/pact-gateway/internal/internalui"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
	"github.com/pact-cloud/pact-gateway/internal/internalui/ownermcp"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/node"
	"github.com/pact-cloud/pact-gateway/internal/services/integrationchain"
	"github.com/pact-cloud/pact-gateway/internal/services/presence"
	"github.com/pact-cloud/pact-gateway/internal/tunnel"
)

// tunnelExtra collects adapter settings from the environment:
// `PACT_TUNNEL_AUTH_KEY` becomes `auth_key`. Secrets belong in the keyring or
// the environment, never in the config file (SPEC §12.2).
func tunnelExtra(lookup func(string) []string) map[string]string {
	const prefix = "PACT_TUNNEL_"
	out := map[string]string{}
	for _, kv := range lookup("") {
		i := strings.IndexByte(kv, '=')
		if i <= 0 || !strings.HasPrefix(kv, prefix) {
			continue
		}
		key := strings.ToLower(strings.TrimPrefix(kv[:i], prefix))
		if key == "" {
			continue
		}
		out[key] = kv[i+1:]
	}
	return out
}

// startTunnel resolves and starts the inbound adapter. The returned name is
// what the LAN guard and the trusted-header rule key off (SPEC §5.7).
//
// One case is deliberately not fatal: `direct` with no `public_url` yet. That
// is exactly the first-run state (SPEC §12.4) — the owner has not told the node
// its externally reachable base, and the place they do that is the portal this
// same command is about to serve. Dying there would make the node unstartable
// until someone hand-edited a config file. Any OTHER adapter failing IS fatal:
// the owner asked for a tunnel, and silently serving without one would be a lie
// about reachability.
func startTunnel(ctx context.Context, cfg *core.Config, stored map[string]string) (string, tunnel.Adapter, tunnel.Info, error) {
	name := cfg.Tunnel
	if name == "" {
		name = "direct"
	}
	if name == "direct" && cfg.PublicURL == "" {
		return name, noTunnel{}, tunnel.Info{}, nil
	}
	// Adapter settings come from the portal (`tunnel.<adapter>.<key>` rows) and
	// from the environment, environment last so it still wins (SPEC §12.2).
	extra := map[string]string{}
	prefix := "tunnel." + name + "."
	for k, v := range stored {
		if strings.HasPrefix(k, prefix) {
			extra[strings.TrimPrefix(k, prefix)] = v
		}
	}
	for k, v := range tunnelExtra(func(string) []string { return os.Environ() }) {
		extra[k] = v
	}
	ad, err := tunnel.New(name, tunnel.Options{
		PublicBind: cfg.PublicBind, PublicURL: cfg.PublicURL, Extra: extra,
	})
	if err != nil {
		return name, nil, tunnel.Info{}, err
	}
	info, err := ad.Start(ctx)
	if err != nil {
		return name, nil, tunnel.Info{}, err
	}
	// An adapter that allocates its own hostname is the authority on the public
	// URL; an owner-configured one wins over nothing.
	if info.PublicURL != "" && cfg.PublicURL == "" {
		cfg.PublicURL = info.PublicURL
	}
	return name, ad, info, nil
}

// internalHandler is the internal surface: the portal (CSRF-protected, session
// or loopback authenticated) plus the owner MCP endpoint, which authenticates
// by bearer token and therefore sits OUTSIDE the CSRF wrapper — a token in an
// Authorization header is not something a browser can be tricked into sending
// (SPEC §8.3, §8.4).
func internalHandler(ctx context.Context, nd *node.Node, st store.Store, setup *internalui.SetupTokens,
	tokens *auth.TokenService, authSvc *auth.Service,
	chain *integrationchain.Chain, connector *integrations.Connector, agent *integrations.AgentAnswered,
	presence *presence.Tracker, identityDeps internalui.IdentityDeps,
	setStatic, setOAuthClient func(ctx context.Context, integrationID, a, b string) error,
	auditFn func(action, resource, outcome string), publicURL string,
	settings internalui.SettingsDeps, authDeps *internalui.AuthDeps,
	cfg *core.Config) http.Handler {
	// Everything below is owner-initiated by construction: it is the internal
	// surface. auditFn arrives already tagged.

	mounts := []func(*http.ServeMux){
		func(mux *http.ServeMux) {
			internalui.MountManagePages(mux, internalui.ManageDeps{
				Store: st, Contacts: contactsManager(st, nd), Audit: auditFn,
				// A tier change must reach the live per-caller surface (see ManageDeps).
				Invalidate: nd.Invalidate,
				// the SAME card peers receive, never a second rendering
				Card: nd.Card,
				// Live, not captured: the owner can change it in Settings while
				// the node serves, and an invite that carries a stale base is a
				// link that goes to the wrong place.
				PublicURL: nd.PublicURL,
				// Telling the peer is the other half of approving them: without
				// it they sit at pending_out forever (E26).
				Approved: func(ctx context.Context, accountID, contactFpr string, granted []string) error {
					ci := newContactInitiator(st, nd, auditFn)
					return ci.NotifyApproved(ctx, accountID, contactFpr, granted)
				},
				// And the other answer, for the same reason (review P-13).
				Rejected: func(ctx context.Context, accountID, contactFpr string) error {
					return newContactInitiator(st, nd, auditFn).NotifyRejected(ctx, accountID, contactFpr)
				},
				SignCard: func(accountID, cardText string) (string, error) {
					return nd.SignCard(ctx, accountID, cardText)
				},
			})
		},
		func(mux *http.ServeMux) {
			// Settings · identity (SPEC §8.2, §3.9): the node's identities and their
			// certificates, and creating one by the SAME procedure the CLI runs.
			internalui.MountIdentityPages(mux, identityDeps)
		},
		func(mux *http.ServeMux) {
			internalui.MountContactPages(mux, internalui.ContactsDeps{
				// What the node's own surface gates tools with — the core five
				// plus every live integration's `integration.<slug>` — so the
				// switchboard can grant what this node can actually serve.
				ServedPermissions: nd.ServedPermissions,
				Store:             st, Invalidate: nd.Invalidate, Audit: auditFn,
				// One contact's card, re-fetched because somebody pressed the button: the
				// same function the owner MCP's refresh_contact calls.
				RefreshContact: refreshContact(nd),
				// A contact's tools, and calling them: the node's one outbound path.
				ListTools: func(ctx context.Context, accountID, fpr string) ([]internalui.ContactTool, error) {
					tools, err := nd.ListContactTools(ctx, accountID, fpr)
					if err != nil {
						return nil, err
					}
					out := make([]internalui.ContactTool, 0, len(tools))
					for _, t := range tools {
						out = append(out, internalui.ContactTool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
					}
					return out, nil
				},
				Call: nd.CallContact,
				// The SAME function the owner MCP's add_contact calls, so the
				// portal and the agent surface cannot disagree about what
				// accepting an invite, or asking from a card, does (SPEC §8.4).
				AddContact: func(ctx context.Context, accountID, inviteURL, card, note, grant string) (string, string, error) {
					res, err := newContactInitiator(st, nd, auditFn).Add(ctx, accountID, inviteURL, card, note, grant)
					if err != nil {
						return "", "", err
					}
					return res.Fingerprint, res.Status, nil
				},
			})
		},
		func(mux *http.ServeMux) {
			// The conversation view. Messaging worked end to end and had no way
			// in: /inbox listed threads that already existed, so an owner could
			// reply and never start.
			internalui.MountMessagePages(mux, internalui.MessagesDeps{
				Store: st, Send: nd.SendMessage, SendMedia: nd.SendMedia, Audit: auditFn,
			})
		},
		func(mux *http.ServeMux) {
			internalui.MountMediaPages(mux, internalui.MediaDeps{
				Store: st, Blobs: messaging.BlobDir{Root: filepath.Join(cfg.DataDir, "blobs")},
				Fetch: nd.FetchMedia, Audit: auditFn,
			})
			internalui.MountInboxPages(mux, internalui.InboxDeps{
				Store: st, Msg: &messaging.Service{Store: st, Bus: nd.Bus()},
				Bus:  nd.Bus(),
				Send: nd.SendMessage,
			})
		},
		func(mux *http.ServeMux) {
			// The SAME chain the node runs: the portal used to build its own
			// Cataloger and Exposures with every hook nil, so an exposure the
			// owner published here changed nothing anywhere else.
			internalui.MountIntegrationPages(mux, internalui.IntegrationsDeps{
				Store: st, Manager: chain.Manager, Connector: connector,
				Exposures:      chain.Exposures,
				Cataloger:      chain.Cataloger,
				Audit:          auditFn,
				SetStatic:      setStatic,
				SetOAuthClient: setOAuthClient,
			})
		},
		func(mux *http.ServeMux) { internalui.MountAuditPages(mux, st) },
		func(mux *http.ServeMux) {
			internalui.MountDashboard(mux, internalui.DashboardDeps{
				Store: st,
				Setup: setup,
				// Only offer to sign out of a session that exists: a loopback
				// portal serves with no login at all (SPEC §8.3).
				SignedIn: func(r *http.Request) bool {
					return internalui.OwnerFrom(r.Context()) != ""
				},
				Posture: func() internalui.DashboardPosture {
					return internalui.DashboardPosture{
						Mode: string(cfg.Mode), Seal: string(cfg.Seal),
						ClientCert: string(cfg.ClientCert), Tunnel: cfg.Tunnel,
						PublicURL: nd.PublicURL(),
					}
				},
				// The newest rows, newest first, as a PAGE. This read the whole chain on every render of
				// the dashboard and kept the last few.
				Recent: func(ctx context.Context, limit int) ([]store.AuditRow, error) {
					return st.ListAuditEventsPage(ctx, store.AuditPage{Limit: limit})
				},
			})
		},
		func(mux *http.ServeMux) { internalui.MountSettingsPages(mux, settings) },
		func(mux *http.ServeMux) {
			internalui.MountOwnerPages(mux, internalui.OwnersDeps{
				Store: st, Tokens: tokens, Audit: auditFn,
				Passkeys: authSvc.ListPasskeys, Remove: authSvc.RemovePasskey,
			})
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/owner/mcp", ownerMCPHandler(ctx, nd, st, tokens, authSvc, chain, agent, presence, auditFn))
	mux.Handle("/", internalui.HandlerWithAuth(st, setup, authDeps, mounts...))
	return mux
}

// ownerMCPHandler serves the owner's agent surface: one MCP server per bearer
// identity, so a token scoped to one account can never reach another (SPEC §8.4).
func ownerMCPHandler(ctx context.Context, nd *node.Node, st store.Store,
	tokens *auth.TokenService, authSvc *auth.Service, chain *integrationchain.Chain,
	agent *integrations.AgentAnswered, presence *presence.Tracker,
	auditFn func(action, resource, outcome string)) http.Handler {

	inner := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		ident, ok := ownerIdentity(r, tokens)
		if !ok {
			return nil
		}
		// Account-agnostic services: every method takes the account id, and the
		// token identity is what scopes it (SPEC §8.4).
		srv := ownermcp.NewServerWithExtra(ownermcp.Deps{
			Store: st, Msg: &messaging.Service{Store: st, Bus: nd.Bus()}, PublicURL: nd.PublicURL,
			// Without this an approval made by the owner's AGENT writes the store
			// while the cached per-caller server keeps serving the old tier, so
			// the contact stays at guest tier until the node restarts (P14-05e).
			Invalidate: nd.Invalidate,
			Bus:        nd.Bus(), Contacts: contactsManager(st, nd), Pending: agent,
			Send:           nd.SendMessage,
			Audit:          auditFn,
			RefreshContact: refreshContact(nd),
			// The SAME notification the portal's approve path uses: approving on
			// one surface and not the other would strand the peer depending on
			// which button the owner pressed (E28).
			Approved: func(ctx context.Context, accountID, contactFpr string, granted []string) error {
				ci := newContactInitiator(st, nd, auditFn)
				return ci.NotifyApproved(ctx, accountID, contactFpr, granted)
			},
			Rejected: func(ctx context.Context, accountID, contactFpr string) error {
				return newContactInitiator(st, nd, auditFn).NotifyRejected(ctx, accountID, contactFpr)
			},
			// Removal tells an active contact through the node's one outbound path, the same
			// call the portal's Remove makes.
			Removed: func(ctx context.Context, accountID, contactFpr string) error {
				_, err := nd.CallContact(ctx, accountID, contactFpr, "remove_contact", map[string]any{})
				return err
			},
			// The switchboard the portal offers, so set_permissions can grant an integration.
			ServedPermissions: nd.ServedPermissions,
		}, ownerExtra(nd, st, authSvc, chain, auditFn), ident)
		ownermcp.ForwardBus(ctx, srv, nd.Bus())
		presence.Add(srv)
		auditFn("owner_mcp", "owner:"+ident.OwnerID, "connected")
		return srv
	}, &mcp.StreamableHTTPOptions{
		// SPEC §8.5: stateful, with an EventStore, "so a client that reconnects
		// replays missed notifications instead of losing them". Without one, an
		// owner's agent that dropped its connection silently missed every
		// resource notification sent while it was away — the exact case
		// subscriptions exist for.
		EventStore: mcp.NewMemoryEventStore(nil),
	})
	return requireOwnerToken(tokens, auditFn, inner)
}

// ownerIdentity resolves the bearer token on a request, or reports refusal.
func ownerIdentity(r *http.Request, tokens *auth.TokenService) (auth.Identity, bool) {
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	if presented == "" {
		return auth.Identity{}, false
	}
	ident, err := tokens.Validate(r.Context(), presented)
	if err != nil {
		return auth.Identity{}, false
	}
	return ident, true
}

// requireOwnerToken validates the bearer token on EVERY request.
//
// The check used to live only in the SDK's getServer callback, which runs solely
// for a request carrying no session id. So an established session was never
// re-checked: `token revoke` did not end it, though SPEC §3.4 says revocation
// "takes effect immediately", and anyone holding the session id could drive the
// owner MCP with no Authorization header at all. This endpoint is deliberately
// mounted outside the portal's session and CSRF layers, so the bearer check is
// the only gate there is — and a gate that runs once is not a gate.
func requireOwnerToken(tokens *auth.TokenService, auditFn func(action, resource, outcome string), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if presented == "" {
			auditFn("owner_mcp", "token:none", "identity_required")
			http.Error(w, "a bearer token is required", http.StatusUnauthorized)
			return
		}
		if _, err := tokens.Validate(r.Context(), presented); err != nil {
			// Covers unknown, malformed and REVOKED: the same answer, because
			// distinguishing them tells a caller which guess was closer.
			auditFn("owner_mcp", "token:invalid", "permission_denied")
			http.Error(w, "that token is not valid", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refreshContact hands the portal and the owner MCP the node's one-contact refresh in the plain
// shape both take, so neither surface imports the node and the two cannot answer differently.
func refreshContact(nd *node.Node) func(ctx context.Context, accountID, contactFpr string) (outcome, why string, err error) {
	return func(ctx context.Context, accountID, contactFpr string) (string, string, error) {
		found, err := nd.RefreshContact(ctx, accountID, contactFpr)
		return found.Outcome, found.Why, err
	}
}

// landingPage is the invite landing page (SPEC §9.2) the node serves at /i/{token}: the portal's,
// over what the node supplies. It is handed to the node as node.Options.Landing so that the node
// does not import the portal. The two deps types have the same fields, so a field added to one
// and not the other stops this conversion compiling.
func landingPage(d node.LandingDeps) http.Handler {
	return internalui.LandingHandler(internalui.LandingDeps(d))
}

// contactsManager builds a contacts manager whose approval-awaiting events reach
// the bus, so `pact://requests` and the portal's live view actually fire
// (SPEC §8.5, §9.1). Nothing produced that event before.
func contactsManager(st store.Store, nd *node.Node) *contacts.Manager {
	return &contacts.Manager{
		Store: st,
		OnRequest: func(accountID, contactFpr string) {
			nd.Bus().Publish(messaging.Event{
				Kind: messaging.EventRequest, AccountID: accountID, ContactFpr: contactFpr,
			})
		},
	}
}

// noTunnel stands in for "no inbound adapter is running": a direct-mode node
// that has not been told its public URL yet still serves, it just advertises
// no endpoint on its card until the owner sets one.
type noTunnel struct{}

func (noTunnel) Start(context.Context) (tunnel.Info, error) { return tunnel.Info{}, nil }
func (noTunnel) Stop() error                                { return nil }
func (noTunnel) Status() tunnel.Status {
	return tunnel.Status{Name: "direct", Running: false,
		Detail: "no public_url configured yet — set one in the portal (Settings → Tunnel) so your card can carry an endpoint"}
}

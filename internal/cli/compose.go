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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core"
	"github.com/tech-sumit/pact-gateway/internal/core/audit"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/internalui"
	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
	"github.com/tech-sumit/pact-gateway/internal/internalui/ownermcp"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
	"github.com/tech-sumit/pact-gateway/internal/node"
	"github.com/tech-sumit/pact-gateway/internal/tunnel"
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

// auditWriter turns the hash-chain writer into the three-argument sink every
// surface takes. A failed audit write is reported, never swallowed silently:
// SPEC §11 forbids responding without one, and losing the chain is the kind of
// failure an operator must see.
func auditWriter(ctx context.Context, st store.Store, stderr io.Writer) *auditSink {
	// A container's log IS its operating surface, and this node printed six lines
	// of banner and then nothing: an owner watching `docker logs` had no way to
	// see a refusal, an approval, or a failed delivery, and the audit CLI cannot
	// read the chain while the node holds the data directory. So every event is
	// mirrored to stderr as it is written.
	//
	// It mirrors the audit row and nothing else, which is what makes it safe: the
	// chain records the KEY of a setting and never its value, fingerprints rather
	// than names, and content-addressed references rather than bodies. Nothing
	// leaves the machine — `PACT_LOG=off` silences it for anyone who wants that.
	return &auditSink{w: &audit.Writer{Sink: st}, ctx: ctx, stderr: stderr,
		mirror: os.Getenv("PACT_LOG") != "off"}
}

// auditSink writes to the one hash chain, tagging each event with WHO caused it.
// The actor kind is not decoration: the audit page filters on it, and a chain
// that records "a peer changed this node's seal policy" cannot answer the
// question an operator actually asks — what did I do, and what was done to me.
type auditSink struct {
	w      *audit.Writer
	ctx    context.Context
	stderr io.Writer
	mirror bool
}

func (a *auditSink) as(kind string) func(action, resource, outcome string) {
	// Recover the account the same way the kinded path does. Only that path
	// used to do it, and almost nothing goes through it: every row the public
	// tool surface writes — messages, media, bookings, the traffic that is
	// actually about somebody — was landing with an empty account, which made
	// both §11.6's token scoping and the portal's account scoping vacuous.
	return func(action, resource, outcome string) {
		a.forAccount(accountFromResource(resource), kind)(action, resource, outcome)
	}
}

// forAccount is `as` with the account the event belongs to.
//
// Every row used to be written with an empty account, which made §11.6's
// per-account audit scoping vacuous: `audit_query` permitted a row when it had
// no account, and no row ever had one, so a token narrowed to a single account
// read the whole node's chain. The column is the filter, so it has to be filled
// wherever the account is known.
func (a *auditSink) forAccount(accountID, kind string) func(action, resource, outcome string) {
	return func(action, resource, outcome string) {
		if err := a.w.Append(a.ctx, accountID, kind, "", action, resource, outcome, "", ""); err != nil {
			fmt.Fprintf(a.stderr, "audit: %s %s %s: %v\n", action, resource, outcome, err)
			return
		}
		if a.mirror {
			if resource == "" {
				fmt.Fprintf(a.stderr, "%s %s %s\n", kind, action, outcome)
				return
			}
			fmt.Fprintf(a.stderr, "%s %s %s %s\n", kind, action, resource, outcome)
		}
	}
}

// System: the node's own lifecycle — listeners, adapters, refusals not tied to
// a resolved caller. The vocabulary is the store's (`owner`, `token`, `contact`,
// `guest`, `cli`, `system`); anything outside it is rejected by the schema, so
// this is deliberately not free-form.
func (a *auditSink) system() func(action, resource, outcome string) { return a.as("system") }

// Kinded lets a caller name the actor per event. Unknown kinds fall back to
// `system` rather than being written: the store rejects anything outside its
// vocabulary, and a rejected write is a hole in the chain.
func (a *auditSink) kinded() func(kind, action, resource, outcome string) {
	allowed := map[string]bool{
		"owner": true, "token": true, "contact": true, "guest": true, "cli": true, "system": true,
	}
	return func(kind, action, resource, outcome string) {
		if !allowed[kind] {
			kind = "system"
		}
		a.as(kind)(action, resource, outcome)
	}
}

// Owner: everything reached through the portal or the owner MCP.
func (a *auditSink) owner() func(action, resource, outcome string) { return a.as("owner") }

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
	chain *integrationChain, connector *integrations.Connector, agent *integrations.AgentAnswered,
	presence *ownerPresence, identityDeps internalui.IdentityDeps,
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
				// The SAME redeemer the owner MCP's add_contact calls, so the
				// portal and the agent surface cannot disagree about what
				// accepting an invite does (SPEC §8.4).
				AddContact: func(ctx context.Context, accountID, inviteURL, grant string) (string, error) {
					ci := newContactInitiator(st, nd, auditFn)
					res, err := ci.RedeemInvite(ctx, accountID, inviteURL, grant)
					if err != nil {
						return "", err
					}
					return res.Fingerprint, nil
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
				Recent: func(ctx context.Context, limit int) ([]store.AuditRow, error) {
					rows, err := st.ListAuditEvents(ctx, "")
					if err != nil {
						return nil, err
					}
					if len(rows) > limit {
						rows = rows[len(rows)-limit:]
					}
					// newest first
					for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
						rows[i], rows[j] = rows[j], rows[i]
					}
					return rows, nil
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
	tokens *auth.TokenService, authSvc *auth.Service, chain *integrationChain,
	agent *integrations.AgentAnswered, presence *ownerPresence,
	auditFn func(action, resource, outcome string)) http.Handler {

	inner := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		ident, ok := ownerIdentity(r, tokens)
		if !ok {
			return nil
		}
		// Account-agnostic services: every method takes the account id, and the
		// token identity is what scopes it (SPEC §8.4).
		srv := ownermcp.NewServerWithExtra(ownermcp.Deps{
			Store: st, Msg: &messaging.Service{Store: st, Bus: nd.Bus()},
			// Without this an approval made by the owner's AGENT writes the store
			// while the cached per-caller server keeps serving the old tier, so
			// the contact stays at guest tier until the node restarts (P14-05e).
			Invalidate: nd.Invalidate,
			Bus:        nd.Bus(), Contacts: contactsManager(st, nd), Pending: agent,
			Send:         nd.SendMessage,
			Audit:        auditFn,
			SyncContacts: nd.SyncContacts,
			// The SAME notification the portal's approve path uses: approving on
			// one surface and not the other would strand the peer depending on
			// which button the owner pressed (E28).
			Approved: func(ctx context.Context, accountID, contactFpr string, granted []string) error {
				ci := newContactInitiator(st, nd, auditFn)
				return ci.NotifyApproved(ctx, accountID, contactFpr, granted)
			},
		}, ownerExtra(nd, st, authSvc, chain, auditFn), ident)
		ownermcp.ForwardBus(ctx, srv, nd.Bus())
		presence.add(srv)
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

// accountFromResource recovers the account id the node prefixes into a resource
// string (`account:<id> …`). It is a recovery rather than a redesign: the
// prefix already carries the fact, and threading a second parameter through
// every audit call site would touch far more code than the filter needs.
func accountFromResource(resource string) string {
	const prefix = "account:"
	if !strings.HasPrefix(resource, prefix) {
		return ""
	}
	rest := resource[len(prefix):]
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		return rest[:i]
	}
	return rest
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

// newAgentAnswered builds the agent-answered service together with the tracker
// that answers its Connected question (SPEC §6.8).
//
// They are created together on purpose. The tracker used to be made inside
// ownerMCPHandler, which `serve` does not build until AFTER nd.Start has opened
// the PUBLIC listener and the stored integrations have been reconnected — and
// reconnecting is exactly what republishes agent-answered exposures. So for the
// whole of boot, Connected was nil again and a contact calling an agent-answered
// capability was held for the full wait budget: the defect P12-11 fixed,
// reachable through the startup window it left behind. Pairing them here means
// there is no moment when one exists without the other.
func newAgentAnswered(st store.Store, audit func(action, resource, outcome string)) (*integrations.AgentAnswered, *ownerPresence) {
	presence := &ownerPresence{}
	return &integrations.AgentAnswered{
		Store: st, Audit: audit,
		Connected: func(string) bool { return presence.any() },
	}, presence
}

// ownerPresence answers "is the owner's agent attached right now?" (SPEC §6.8).
//
// The owner MCP is account-agnostic — the token identity scopes each call, not
// the server — so this is deliberately a node-wide answer and the account id is
// ignored. Servers are registered as they are created and pruned once they hold
// no sessions, so a reconnecting agent does not accumulate entries.
type ownerPresence struct {
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	entries []*presenceEntry
}

type presenceEntry struct {
	srv *mcp.Server
	// added is when the server was registered. A server is created by getServer
	// BEFORE the SDK attaches its session, so pruning on "has no sessions" alone
	// would discard a live agent in the gap between the two — and that agent
	// would then never count. Give a new server a grace period to acquire one.
	added time.Time
	// saw records that this server HAS held a session. Once true, "no sessions"
	// means the agent left rather than has not arrived, and it can go at once.
	saw bool
}

// presenceGrace is how long a newly created server may hold no session before it
// is treated as abandoned.
const presenceGrace = time.Minute

func (p *ownerPresence) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *ownerPresence) add(s *mcp.Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, &presenceEntry{srv: s, added: p.now()})
}

func (p *ownerPresence) any() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	live := p.entries[:0]
	found := false
	for _, e := range p.entries {
		has := false
		for range e.srv.Sessions() {
			has = true
			break
		}
		switch {
		case has:
			e.saw = true
			live = append(live, e)
			found = true
		case !e.saw && now.Sub(e.added) < presenceGrace:
			live = append(live, e) // still arriving
		}
	}
	p.entries = live
	return found
}

package internalui

// Integration pages (SPEC §6.3 portal Connect flow, §8.2): list + add, the
// Connect hand-off to the authorization server, and the OAuth callback. The
// exposure picker is P3-06; these pages own only lifecycle and auth.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

type IntegrationsDeps struct {
	Store     store.Store
	Manager   *integrations.Manager
	Connector *integrations.Connector
	Exposures *integrations.Exposures
	Cataloger *integrations.Cataloger
	Audit     func(action, resource, outcome string)
	// ConnectTimeout bounds the wait for the AS URL (default 15 s).
	ConnectTimeout time.Duration
	// SetStatic stores an `auth: static` integration's sealed credential
	// (SPEC §6.3). nil hides the control rather than offering a dead one.
	SetStatic func(ctx context.Context, integrationID, header, value string) error
	// SetOAuthClient registers the pre-registered OAuth client §6.3 falls back
	// to when no Client ID Metadata Document is hosted (escalation E4).
	SetOAuthClient func(ctx context.Context, integrationID, clientID, clientSecret string) error
	// Background runs work that outlives the request that starts it — a Connect's dial, which for
	// an OAuth upstream waits minutes for the owner to sign in — in the node's joined group, with
	// the group's context (serve's startBackground). Required: a bare goroutine went on writing to
	// the store after the portal, and the store, had stopped.
	Background func(work func(ctx context.Context))
}

// checkIntegration refuses an integration that could never connect. Each
// transport needs a different thing, and a row without it is not a configuration
// an owner can fix later — it is one they cannot even see the shape of.
func checkIntegration(slug, transport, endpoint, command string) error {
	if slug == "" {
		return fmt.Errorf("give it a name (slug), so you can tell it apart from the others")
	}
	// The slug is what its permission, integration.<slug>, names (HDTP §8). One that permission
	// cannot spell was created and then could never be granted to a contact.
	if !contacts.ValidIntegrationSlug(slug) {
		return fmt.Errorf("the name (slug) is lowercase letters, digits and hyphens, starting with a letter or digit, 63 characters at most")
	}
	switch transport {
	case "streamable-http", "sse":
		if endpoint == "" {
			return fmt.Errorf("a %s integration needs an endpoint URL to connect to", transport)
		}
		if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
			return fmt.Errorf("the endpoint should be an http(s) URL")
		}
	case "stdio-supervised":
		if command == "" {
			return fmt.Errorf("a stdio integration needs a command to run")
		}
	default:
		return fmt.Errorf("choose a transport")
	}
	return nil
}

func MountIntegrationPages(mux *http.ServeMux, d IntegrationsDeps) {
	if d.Background == nil {
		panic("internalui: MountIntegrationPages needs Background, the node's joined group for work a request starts")
	}
	timeout := d.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	audit := d.Audit
	if audit == nil {
		audit = func(_, _, _ string) {}
	}

	mux.HandleFunc("GET /api/integrations", d.getAPIIntegrations)
	mux.HandleFunc("POST /integrations/{id}/oauth-client", d.postIntegrationsIDOAuthClient(audit))
	mux.HandleFunc("POST /integrations/{id}/credential", d.postIntegrationsIDCredential(audit))
	mux.HandleFunc("POST /integrations/create", d.postIntegrationsCreate(audit))
	mux.HandleFunc("POST /integrations/{id}/remove", d.postIntegrationsIDRemove(audit))
	mux.HandleFunc("POST /integrations/{id}/connect", d.postIntegrationsIDConnect(timeout))
	mux.HandleFunc("GET /integrations/{id}/authorize", d.getIntegrationsIDAuthorize(timeout))
	mux.HandleFunc("POST /integrations/{id}/refresh", d.postIntegrationsIDRefresh)
	mux.HandleFunc("GET /api/integrations/{id}/exposure", d.getAPIIntegrationsIDExposure)
	mux.HandleFunc("POST /integrations/{id}/exposure", d.postIntegrationsIDExposure(audit))
	mux.HandleFunc("POST /integrations/{id}/reconfirm", d.postIntegrationsIDReconfirm)
	mux.HandleFunc("GET /oauth/callback", d.getOAuthCallback(audit))
}

// getAPIIntegrations serves `GET /api/integrations`.
func (d IntegrationsDeps) getAPIIntegrations(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	rows, err := d.Store.ListIntegrations(r.Context(), account)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	apiJSON(w, map[string]any{
		"rows": rows, "can_set_static": d.SetStatic != nil, "can_set_oauth": d.SetOAuthClient != nil,
	})
}

// postIntegrationsIDOAuthClient serves `POST /integrations/{id}/oauth-client`.
func (d IntegrationsDeps) postIntegrationsIDOAuthClient(audit func(action string, resource string, outcome string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.SetOAuthClient == nil {
			http.Error(w, "OAuth clients are not configurable on this node", http.StatusServiceUnavailable)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		id := r.PathValue("id")
		if err := d.SetOAuthClient(r.Context(), id,
			strings.TrimSpace(r.PostForm.Get("client_id")), r.PostForm.Get("client_secret")); err != nil {
			audit("oauth_client", withAccount(r, "integration:"+id), "error")
			http.Error(w, "could not store that client", http.StatusBadRequest)
			return
		}
		audit("oauth_client", withAccount(r, "integration:"+id), "stored")
		http.Redirect(w, r, "/integrations?account="+accountParam(r), http.StatusSeeOther)
	}
}

// postIntegrationsIDCredential serves `POST /integrations/{id}/credential`.
func (d IntegrationsDeps) postIntegrationsIDCredential(audit func(action string, resource string, outcome string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.SetStatic == nil {
			http.Error(w, "static credentials are not configured on this node", http.StatusServiceUnavailable)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		id := r.PathValue("id")
		header := strings.TrimSpace(r.PostForm.Get("header"))
		value := r.PostForm.Get("value")
		if err := d.SetStatic(r.Context(), id, header, value); err != nil {
			// The value never appears in an error, a log line or an audit row.
			audit("static_credential", withAccount(r, "integration:"+id), "error")
			http.Error(w, "could not store that credential", http.StatusBadRequest)
			return
		}
		audit("static_credential", withAccount(r, "integration:"+id), "stored")
		http.Redirect(w, r, "/integrations?account="+accountParam(r), http.StatusSeeOther)
	}
}

// postIntegrationsCreate serves `POST /integrations/create`.
func (d IntegrationsDeps) postIntegrationsCreate(audit func(action string, resource string, outcome string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		account := accountParam(r)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// Nothing was validated here, so pressing Add on an empty form created a
		// row with no slug and nothing to dial: it showed as `— streamable-http —
		// disabled`, Connect tried to reach "", and there was no way to remove it.
		slug := strings.TrimSpace(r.PostForm.Get("slug"))
		transport := r.PostForm.Get("transport")
		endpoint := strings.TrimSpace(r.PostForm.Get("endpoint"))
		command := strings.TrimSpace(r.PostForm.Get("command"))
		if err := checkIntegration(slug, transport, endpoint, command); err != nil {
			audit("integration_create", withAccount(r, "integration:"+slug), "refused")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		in, err := d.Store.InsertIntegration(r.Context(), store.Integration{
			AccountID: account, Slug: slug,
			Transport: transport, Endpoint: endpoint,
			Command: command, AuthKind: r.PostForm.Get("auth_kind"),
		})
		if err != nil {
			audit("integration_create", withAccount(r, "integration:"+r.PostForm.Get("slug")), "error")
			http.Error(w, "create failed (duplicate slug?)", http.StatusConflict)
			return
		}
		audit("integration_create", withAccount(r, "integration:"+in.Slug), "ok")
		http.Redirect(w, r, "/integrations?account="+account, http.StatusSeeOther)
	}
}

// postIntegrationsIDRemove serves `POST /integrations/{id}/remove`.
//
// Removing one. DeleteIntegration existed in the store from the start and had
// no route, so an integration added by mistake was permanent.
func (d IntegrationsDeps) postIntegrationsIDRemove(audit func(action string, resource string, outcome string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		account := accountParam(r)
		// The id comes from the caller. Without this check any account could
		// delete any other account's integration by guessing one.
		in, err := d.Store.GetIntegrationByID(r.Context(), id)
		if err != nil || in.AccountID != account {
			audit("integration_remove", withAccount(r, "integration:"+id), "refused")
			http.Error(w, "that integration belongs to another account", http.StatusForbidden)
			return
		}
		if err := d.Store.DeleteIntegration(r.Context(), id); err != nil {
			audit("integration_remove", withAccount(r, "integration:"+in.Slug), "error")
			http.Error(w, "could not remove it", http.StatusInternalServerError)
			return
		}
		audit("integration_remove", withAccount(r, "integration:"+in.Slug), "ok")
		http.Redirect(w, r, "/integrations?account="+account, http.StatusSeeOther)
	}
}

// postIntegrationsIDConnect serves `POST /integrations/{id}/connect`.
//
// Connect starts the dial in the background; for OAuth upstreams the dial
// blocks inside the code fetcher until the callback lands.
func (d IntegrationsDeps) postIntegrationsIDConnect(timeout time.Duration) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		account := accountParam(r)
		if d.Connector != nil {
			d.Connector.SetOrigin(id, browserOrigin(r))
		}
		// Read the row before the connect starts, so that once it has, the
		// JSON path below goes straight to waiting for the authorization URL.
		in, err := d.Store.GetIntegrationByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		d.Background(func(bg context.Context) {
			ctx, cancel := context.WithTimeout(bg, 5*time.Minute)
			defer cancel()
			// Reconnect, not Connect: this is the owner's decision, the one thing that re-arms a
			// supervised child that gave up (SPEC §6.2).
			if err := d.Manager.Reconnect(ctx, id); err != nil && d.Connector != nil {
				// The authorize request may be waiting on this; tell it why.
				d.Connector.Fail(id, err)
			}
		})
		// The portal asks for JSON and navigates to the provider itself. A form
		// POST answered with a redirect to the provider is blocked by the
		// portal's own CSP: browsers apply `form-action 'self'` to where a form
		// submission ends up, redirects included — and OAuth ends up at the
		// authorization server. A script navigation is not a form action.
		if wantsJSON(r) {
			if in.AuthKind != "oauth" || d.Connector == nil {
				apiJSON(w, map[string]any{"ok": true})
				return
			}
			u, err := d.Connector.AuthorizeURL(r.Context(), id, timeout)
			if err != nil {
				apiJSONStatus(w, http.StatusGatewayTimeout, map[string]any{"error": "authorization did not start: " + err.Error()})
				return
			}
			apiJSON(w, map[string]any{"authorize_url": u})
			return
		}
		http.Redirect(w, r, "/integrations/"+id+"/authorize?account="+account, http.StatusSeeOther)
	}
}

// getIntegrationsIDAuthorize serves `GET /integrations/{id}/authorize`.
//
// authorize waits for the AS URL and bounces the owner's browser to it.
// Non-OAuth integrations connect without one; show the list again.
func (d IntegrationsDeps) getIntegrationsIDAuthorize(timeout time.Duration) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		account := accountParam(r)
		in, err := d.Store.GetIntegrationByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if in.AuthKind != "oauth" || d.Connector == nil {
			http.Redirect(w, r, "/integrations?account="+account, http.StatusSeeOther)
			return
		}
		d.Connector.SetOrigin(id, browserOrigin(r))
		u, err := d.Connector.AuthorizeURL(r.Context(), id, timeout)
		if err != nil {
			http.Error(w, "authorization did not start: "+err.Error(), http.StatusGatewayTimeout)
			return
		}
		http.Redirect(w, r, u, http.StatusSeeOther)
	}
}

// postIntegrationsIDRefresh serves `POST /integrations/{id}/refresh`.
//
// Manual catalog refresh (SPEC §6.4 "on manual refresh from the portal").
func (d IntegrationsDeps) postIntegrationsIDRefresh(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in, err := d.Store.GetIntegrationByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if d.Cataloger == nil {
		http.Error(w, "catalog refresh is not wired", http.StatusConflict)
		return
	}
	if _, _, err := d.Cataloger.Refresh(r.Context(), id); err != nil {
		http.Error(w, "refresh failed: "+err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/integrations/"+id+"/exposure?account="+in.AccountID, http.StatusSeeOther)
}

// getAPIIntegrationsIDExposure serves `GET /api/integrations/{id}/exposure`.
func (d IntegrationsDeps) getAPIIntegrationsIDExposure(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in, err := d.Store.GetIntegrationByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	page, err := d.buildPicker(r, in)
	if err != nil {
		http.Error(w, `{"error":"no catalog snapshot yet — connect first"}`, http.StatusConflict)
		return
	}
	apiJSON(w, page)
}

// postIntegrationsIDExposure serves `POST /integrations/{id}/exposure`.
func (d IntegrationsDeps) postIntegrationsIDExposure(audit func(action string, resource string, outcome string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		in, err := d.Store.GetIntegrationByID(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		page, err := d.buildPicker(r, in)
		if err != nil {
			http.Error(w, "no catalog snapshot", http.StatusConflict)
			return
		}
		var entries []integrations.ExposureEntry
		var riskyChosen []string
		for _, t := range page.Tools {
			if r.PostForm.Get("expose_"+t.Name) == "" {
				continue
			}
			mode := r.PostForm.Get("mode_" + t.Name)
			if mode == "" {
				mode = integrations.ModePassthrough
			}
			entries = append(entries, integrations.ExposureEntry{
				Tool: t.Name, Mode: mode,
				ExposedName: r.PostForm.Get("name_" + t.Name),
				Recipe:      r.PostForm.Get("recipe_" + t.Name),
				Fallback:    r.PostForm.Get("fallback_" + t.Name),
			})
			if t.Risk.Write {
				riskyChosen = append(riskyChosen, t.Name)
			}
		}
		// SPEC §6.9: exposing write-capable tools demands an explicit, RECORDED
		// acknowledgment. Advisory for sorting, mandatory for the ack gate is the
		// portal's own rule — annotations still gate no authorization decision.
		if len(riskyChosen) > 0 && r.PostForm.Get("ack") == "" {
			http.Error(w, "these tools look write-capable: "+strings.Join(riskyChosen, ", ")+
				" — re-submit with the acknowledgment checked. Prefer the narrowest credential that works.",
				http.StatusBadRequest)
			return
		}
		if len(riskyChosen) > 0 {
			audit("exposure_ack", withAccount(r, "integration:"+in.Slug+" ack:"+strings.Join(riskyChosen, ",")), "ok")
		}
		if _, err := d.Exposures.Publish(r.Context(), id, entries); err != nil {
			audit("exposure_publish", withAccount(r, "integration:"+in.Slug), "error")
			http.Error(w, "publish failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/integrations/"+id+"/exposure?account="+in.AccountID, http.StatusSeeOther)
	}
}

// postIntegrationsIDReconfirm serves `POST /integrations/{id}/reconfirm`.
//
// One-click reconfirm of stale entries (SPEC §6.5): named ones, or all.
func (d IntegrationsDeps) postIntegrationsIDReconfirm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	in, err := d.Store.GetIntegrationByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if _, err := d.Exposures.Reconfirm(r.Context(), id, r.PostForm["name"]); err != nil {
		http.Error(w, "reconfirm failed: "+err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/integrations/"+id+"/exposure?account="+in.AccountID, http.StatusSeeOther)
}

// getOAuthCallback serves `GET /oauth/callback`.
//
// The AS redirects here. The registered redirect URI is used verbatim, so
// it cannot name the integration — the OAuth state is what finds the
// waiting flow (states outlive newer flows for stateTTL; a background
// reconnect can no longer orphan the owner's authorize tab). A provider
// that reflects extra query params may still carry ?integration=. iss
// rides through for the handler's RFC 9207 check — never validated here.
func (d IntegrationsDeps) getOAuthCallback(audit func(action string, resource string, outcome string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if d.Connector == nil {
			http.Error(w, "no authorization is pending", http.StatusBadRequest)
			return
		}
		// The provider sends back exactly the registered redirect URI plus
		// code and state; the state is what names the waiting flow.
		id := q.Get("integration")
		if id == "" {
			id, _ = d.Connector.IntegrationForState(q.Get("state"))
		}
		if id == "" {
			http.Error(w, "no authorization is pending for this callback", http.StatusBadRequest)
			return
		}
		d.Connector.Deliver(id, auth.AuthorizationResult{
			Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss"),
		})
		audit("integration_oauth_callback", withAccount(r, "integration:"+id), "ok")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>Connected · hdtp-gateway</title>` + portalStyle + `</head><body><main>` + portalBrand + `<h1>Authorization received</h1><p>The node is finishing the connection. Go back to the portal tab — it updates on its own — and close this one.</p></main></body></html>`))
	}
}

// pickerTool is one left-column row: definition + advisory risk + suggestions.
type pickerTool struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Risk        integrations.Risk `json:"risk"`
	Suggestion  string            `json:"suggestion"` // recipe pre-selection (SPEC §6.7)
	Exposed     bool              `json:"exposed"`
}

type pickerPage struct {
	Integration store.Integration            `json:"integration"`
	Catalog     store.Catalog                `json:"catalog"`
	Tools       []pickerTool                 `json:"tools"` // risk-sorted: read-only first, write-capable last
	Entries     []integrations.ExposureEntry `json:"entries"`
	HasStale    bool                         `json:"has_stale"`
}

func (d IntegrationsDeps) buildPicker(r *http.Request, in store.Integration) (pickerPage, error) {
	cat, err := d.Store.LatestCatalog(r.Context(), in.ID)
	if err != nil {
		return pickerPage{}, err
	}
	var defs []integrations.ToolDef
	if err := json.Unmarshal([]byte(cat.Tools), &defs); err != nil {
		return pickerPage{}, err
	}
	entries, _ := d.Exposures.AllEntries(r.Context(), in.ID)
	exposed := map[string]bool{}
	for _, en := range entries {
		exposed[en.Tool] = true
	}
	tools := make([]pickerTool, 0, len(defs))
	for _, t := range defs {
		tools = append(tools, pickerTool{
			Name: t.Name, Description: t.Description,
			Risk:       integrations.AssessRisk(t.Name, t.Annotations),
			Suggestion: integrations.RecipeSuggestion(t.Name),
			Exposed:    exposed[t.Name],
		})
	}
	sort.SliceStable(tools, func(i, j int) bool {
		return !tools[i].Risk.Write && tools[j].Risk.Write
	})
	hasStale := false
	for _, en := range entries {
		if en.Stale {
			hasStale = true
		}
	}
	return pickerPage{
		Integration: in, Catalog: cat, Tools: tools,
		Entries: entries, HasStale: hasStale,
	}, nil
}

// browserOrigin is scheme://host as the owner's browser sees the portal — the
// only base an OAuth provider can redirect that browser back to.
func browserOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

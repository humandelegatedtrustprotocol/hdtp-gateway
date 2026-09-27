package internalui

// Portal authentication (SPEC §8.3, §8.6): the WebAuthn ceremonies and the
// session they produce.
//
// SPEC §8.6 makes registration portal-only — never over the owner MCP — because
// a bearer-token session cannot perform a WebAuthn ceremony, and the boundary
// also stops a token minting a durable credential for itself. These handlers are
// therefore the only place a passkey is created.
//
// Binding decides authentication and is fixed at startup (§8.3): a loopback
// portal has no login, and a non-loopback one refuses to start without passkeys
// and TLS. That is a startup invariant, so the middleware below captures the
// decision once rather than re-deciding per request. CSRF stays on either way.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

// AuthDeps is what the ceremonies and the session gate need.
type AuthDeps struct {
	Service *auth.Service
	Origin  OriginPolicy
	// Secure marks the session cookie as https-only.
	Secure bool
	Audit  func(action, resource, outcome string)
	// SetupAllowed gates first-passkey registration the way the wizard does:
	// zero passkeys, and loopback or a one-time token. It must NOT consume the
	// token — a ceremony is two requests.
	SetupAllowed func(r *http.Request) bool
	// SetupDone burns the one-time token once a passkey exists.
	SetupDone func(r *http.Request)
}

// cookieTag suffixes both browser cookie names so two nodes on one host do not
// overwrite each other's. Cookies are scoped by host and path, never by port, so
// `localhost:18120` and `localhost:18121` share a jar: without this, logging
// into one signs you out of the other, silently and instantly. Set once at
// startup by SetCookieTag; empty keeps the plain names for a single node.
var cookieTag string

// SetCookieTag records this node's tag (core.Config.Tag).
func SetCookieTag(tag string) { cookieTag = tag }

// sessionCookieName is the session cookie for THIS node.
func sessionCookieName() string {
	if cookieTag == "" {
		return "pact_session"
	}
	return "pact_session_" + cookieTag
}

// csrfCookieName is the CSRF cookie for THIS node. It needs the same treatment:
// a clobbered csrf cookie makes every mutation fail the double-submit check
// while the page still holds the old value.
func csrfCookieName() string {
	if cookieTag == "" {
		return "pact_csrf"
	}
	return "pact_csrf_" + cookieTag
}

func (d AuthDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// setupTmpl is the first-run wizard (SPEC §8.3). It replaces the P2-era
// placeholder that said "Passkey registration arrives with phase P2" and shipped
// no JavaScript at all — so `/setup/begin` and `/setup/finish` worked while no
// browser ever called them, and a real owner could not register a first passkey.
//
// It is hand-written imperative JS for the same reason loginTmpl is: a WebAuthn
// ceremony is a sequence of promises over binary values, which no declarative
// attribute library expresses. Everything is inline; nothing loads from a host.

// MountAuthPages registers the ceremonies and the login page.
func MountAuthPages(mux *http.ServeMux, d AuthDeps) {
	mux.HandleFunc("POST /login/begin", d.postLoginBegin)
	mux.HandleFunc("POST /login/finish", d.postLoginFinish)
	mux.HandleFunc("POST /logout", d.postLogout)
	mux.HandleFunc("POST /setup/begin", d.postSetupBegin)
	mux.HandleFunc("POST /setup/finish", d.postSetupFinish)
}

// postLoginBegin serves `POST /login/begin`.
func (d AuthDeps) postLoginBegin(w http.ResponseWriter, r *http.Request) {
	rp, ok := d.Origin.RelyingParty(r)
	if !ok {
		d.audit("portal_login", "host:"+r.Host, "refused_origin")
		http.Error(w, "this host is not one the node registers passkeys for", http.StatusBadRequest)
		return
	}
	opts, ceremony, err := d.Service.BeginLogin(r.Context(), rp)
	if err != nil {
		http.Error(w, "no passkeys registered", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ceremony": ceremony, "options": opts})
}

// postLoginFinish serves `POST /login/finish`.
func (d AuthDeps) postLoginFinish(w http.ResponseWriter, r *http.Request) {
	token, err := d.Service.FinishLogin(r.Context(), r.URL.Query().Get("ceremony"), r)
	if err != nil {
		d.audit("portal_login", "", "refused")
		http.Error(w, "not accepted", http.StatusUnauthorized)
		return
	}
	d.setSession(w, token)
	d.audit("portal_login", "", "ok")
	writeJSON(w, map[string]string{"status": "ok"})
}

// postLogout serves `POST /logout`.
func (d AuthDeps) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName()); err == nil {
		d.Service.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName(), Value: "", Path: "/", MaxAge: -1})
	d.audit("portal_logout", "", "ok")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// postSetupBegin serves `POST /setup/begin`.
//
// Registration. The gate is the wizard's: zero passkeys plus loopback or a
// one-time token, so this cannot be used to add a credential to a node
// somebody else already owns.
func (d AuthDeps) postSetupBegin(w http.ResponseWriter, r *http.Request) {
	if d.SetupAllowed != nil && !d.SetupAllowed(r) {
		http.Error(w, "setup is closed", http.StatusNotFound)
		return
	}
	rp, ok := d.Origin.RelyingParty(r)
	if !ok {
		d.audit("passkey_register", "host:"+r.Host, "refused_origin")
		http.Error(w, "this host is not one the node registers passkeys for", http.StatusBadRequest)
		return
	}
	opts, ceremony, err := d.Service.BeginRegistration(r.Context(), rp, "", "owner")
	if err != nil {
		http.Error(w, "could not start registration", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ceremony": ceremony, "options": opts})
}

// postSetupFinish serves `POST /setup/finish`.
func (d AuthDeps) postSetupFinish(w http.ResponseWriter, r *http.Request) {
	if d.SetupAllowed != nil && !d.SetupAllowed(r) {
		http.Error(w, "setup is closed", http.StatusNotFound)
		return
	}
	tag := r.URL.Query().Get("tag")
	ownerID, err := d.Service.FinishRegistration(r.Context(),
		r.URL.Query().Get("ceremony"), "", "owner", tag, r)
	if err != nil {
		d.audit("passkey_register", "", "refused")
		http.Error(w, "that passkey was not accepted", http.StatusBadRequest)
		return
	}
	if d.SetupDone != nil {
		d.SetupDone(r)
	}
	// Sign them in on the credential they just proved. Without this, first
	// run ends by asking for the same authenticator a second time — and now
	// that no bind serves the portal without a session (§8.3), that second
	// prompt is the difference between a claimed node and a confused owner
	// staring at a sign-in page.
	if tok, serr := d.Service.MintSession(r.Context(), ownerID); serr == nil {
		d.setSession(w, tok)
	}
	d.audit("passkey_register", "owner:"+ownerID, "ok")
	writeJSON(w, map[string]string{"status": "ok", "owner": ownerID})
}

func (d AuthDeps) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName(), Value: token, Path: "/",
		HttpOnly: true, Secure: d.Secure, SameSite: http.SameSiteStrictMode,
		Expires: time.Now().Add(12 * time.Hour),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

/* ------------------------------- the gate ------------------------------- */

type ownerKey struct{}

// OwnerFrom returns the signed-in owner, or "" on a loopback portal where §8.3
// says there is no login.
func OwnerFrom(ctx context.Context) string {
	id, _ := ctx.Value(ownerKey{}).(string)
	return id
}

// SessionMiddleware resolves the session cookie and refuses everything else.
//
// SPEC §8.3: a session is required on EVERY bind, loopback included. There used
// to be a carve-out — a loopback portal served with no login at all — and it was
// wrong twice over. Reaching loopback is not authentication: every local process
// can open that socket, and the port-forwarding sidecar that makes a loopback
// portal reachable through a tunnel (docs/demos) extends "local" to whoever
// reaches the forwarder. It also made a registered passkey optional in practice,
// which is the opposite of what registering one means.
//
// Ceremony and health routes stay open — a login page nobody can reach is not a
// login page — and so does the static shell that delivers them, which is code,
// not data.
func (d AuthDeps) SessionMiddleware(next http.Handler) http.Handler {
	open := map[string]bool{
		"/login": true, "/login/begin": true, "/login/finish": true,
		"/setup": true, "/setup/begin": true, "/setup/finish": true, "/healthz": true,
		// /api/session answers unauthenticated on purpose: it says only whether
		// a login is required and whether setup is open — what the login and
		// wizard views need to render — and its account list is empty until a
		// session exists (OwnerFrom is "" and membership scoping hides them).
		"/api/session": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookieName()); err == nil && c.Value != "" {
			if owner := d.Service.SessionOwner(r.Context(), c.Value); owner != "" {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ownerKey{}, owner)))
				return
			}
		}
		// The SPA shell and its hashed assets are the login page's own code —
		// refusing them would redirect the sign-in view away from itself. The
		// brand mark and the fonts are part of that shell: the sign-in page
		// itself asks for them before any session exists, so auditing each one
		// as a refused request buried the real refusals under a browser's
		// ordinary asset fetches — dozens of rows per visit, all counted as
		// refusals by the audit view.
		if open[r.URL.Path] || staticShell(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		d.audit("portal_request", "path:"+r.URL.Path, "identity_required")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// A fetch cannot use a login redirect; the SPA routes to sign-in on 401.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"identity_required"}`))
			return
		}
		// Only a VIEW may fall through: serving the SPA shell to a GET hands out
		// static code, and the data behind it still 401s above. A mutating method
		// falling through would reach the actual handler unauthenticated — the
		// old 303-to-login refused those, and refused they stay.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// staticShell reports whether a path is part of the portal's own static shell:
// the hashed bundle, the brand mark, the fonts. These are code and branding the
// sign-in page needs before anyone has signed in, so they are served without a
// session and without an audit row — they carry no owner data to protect.
func staticShell(path string) bool {
	for _, p := range []string{"/assets/", "/fonts/", "/brand/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

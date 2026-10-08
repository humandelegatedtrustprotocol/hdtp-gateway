package internalui

// Portal authentication (SPEC §8.3, §8.6): the WebAuthn ceremonies and the
// session they produce.
//
// SPEC §8.6 makes registration portal-only — never over the owner MCP — because
// a bearer-token session cannot perform a WebAuthn ceremony, and the boundary
// also stops a token minting a durable credential for itself. These handlers are
// therefore the only place a passkey is created.
//
// A session is required on every bind, loopback included (SessionMiddleware); a non-loopback
// bind additionally refuses to start without passkeys and TLS, which the config check enforces
// before this package is built.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

// AuthDeps is what the ceremonies and the session gate need. HandlerWithAuth mounts the
// ceremonies and wraps everything in SessionMiddleware when it is given one.
type AuthDeps struct {
	// Service runs the WebAuthn ceremonies and owns the sessions (auth.Service).
	Service *auth.Service
	// Origin decides which relying party a ceremony runs under; a Host it does not accept is
	// refused with 400 and audited as refused_origin.
	Origin OriginPolicy
	// Secure marks the session cookie as https-only.
	Secure bool
	// Audit records the portal's authentication events and the session gate's refusals.
	// Nil records nothing.
	Audit func(action, resource, outcome string)
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
		return "hdtp_session"
	}
	return "hdtp_session_" + cookieTag
}

// csrfCookieName is the CSRF cookie for THIS node. It needs the same treatment:
// a clobbered csrf cookie makes every mutation fail the double-submit check
// while the page still holds the old value.
func csrfCookieName() string {
	if cookieTag == "" {
		return "hdtp_csrf"
	}
	return "hdtp_csrf_" + cookieTag
}

func (d AuthDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// MountAuthPages registers the five POST endpoints of the ceremonies: /login/begin,
// /login/finish, /logout, /setup/begin and /setup/finish. The pages that drive them are the
// SPA's.
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

// OwnerFrom returns the owner the session gate resolved for this request, or "" when the request
// carries no valid session (a route the gate leaves open, or a handler mounted without
// SessionMiddleware).
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
// What serves without a session is an allow-list: the ceremonies — a login page
// nobody can reach is not a login page — the two pages a browser arrives at from
// another site, the static shell that delivers them and the views the SPA routes
// client-side, which are code, not data (view). Every other route is refused: a
// fetch under /api/ and every mutation with 401, a browser's GET by sending it to
// sign in with the page to come back to.
func (d AuthDeps) SessionMiddleware(next http.Handler, mux *http.ServeMux) http.Handler {
	open := map[string]bool{
		"/login": true, "/login/begin": true, "/login/finish": true,
		"/setup": true, "/setup/begin": true, "/setup/finish": true,
		// /api/session answers unauthenticated on purpose: it says only whether
		// a login is required and whether setup is open — what the login and
		// wizard views need to render — and its account list is empty until a
		// session exists (OwnerFrom is "" and membership scoping hides them).
		"/api/session": true,
		// The web wallet navigates back here cross-site, so the Strict session cookie is not sent
		// with it. The page and its script hold no data; the install they POST to is not open
		// (wallet_pages.go).
		"/wallet/return": true, "/wallet/return.js": true,
		// The OAuth provider redirects the owner's browser back here cross-site, with the same
		// consequence for the cookie. The flow it completes is named by the state the node minted
		// (integrations_pages.go).
		"/oauth/callback": true,
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
		api := strings.HasPrefix(r.URL.Path, "/api/")
		if open[r.URL.Path] || staticShell(r.URL.Path) || (!api && view(mux, r)) {
			next.ServeHTTP(w, r)
			return
		}
		d.audit("portal_request", "path:"+r.URL.Path, "identity_required")
		if api {
			// A fetch cannot use a login redirect; the SPA routes to sign-in on 401.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"identity_required"}`))
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			// The sign-in view returns to `next` once signed in, for a path on this portal
			// (web/src/views/login.tsx).
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		http.Error(w, "sign in first", http.StatusUnauthorized)
	})
}

// view reports whether the SPA's catch-all would serve the request (spa.go): a view the SPA
// routes client-side, or a file at the root of its build. Both are the shell's own code; the
// data a view shows is under /api/, which a session-less request is refused above.
func view(mux *http.ServeMux, r *http.Request) bool {
	_, pattern := mux.Handler(r)
	return pattern == "GET /"
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

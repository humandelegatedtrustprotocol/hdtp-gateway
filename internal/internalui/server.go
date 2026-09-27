// Package internalui implements the internal surface: portal and (later) owner MCP
// (SPEC §8). This file carries the listener plumbing: routing, the setup-wizard gate
// (SPEC §3.1, §8.6, §12.4), and CSRF protection — which stays on even for the
// loopback-no-login rule.
package internalui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// SetupTokens: setup URLs (SPEC §12.4) — ≥128 bits entropy, 24 h expiry, and
// consumed when setup COMPLETES rather than on first use, because a WebAuthn
// ceremony is two requests and burning the token on the first would guarantee
// the second failed. So a token is a bearer credential for the wizard until a
// passkey exists or 24 h pass — not a one-shot. All tokens are invalidated the
// moment any passkey exists (checked at use).
type SetupTokens struct {
	mu     sync.Mutex
	tokens map[string]setupToken
}

type setupToken struct {
	expires time.Time
	// recovery marks a token minted by `passkey reset-wizard` for an owner who
	// lost their passkeys. It is the ONE thing that re-opens the wizard while
	// passkeys still exist (SPEC §3.1, §8.6); an ordinary first-run token never
	// does, so a leftover one cannot be replayed to add an owner later.
	recovery bool
}

func NewSetupTokens() *SetupTokens {
	return &SetupTokens{tokens: map[string]setupToken{}}
}

// Mint issues an ordinary first-run token: usable only while the node has zero
// passkeys.
func (s *SetupTokens) Mint() string { return s.mint(false) }

// MintRecovery issues a token that re-opens the wizard even with passkeys
// present. It is reachable only over the admin unix socket (SPEC §12), whose
// permissions are the host's — the same access that could already read the data
// directory, so this grants no authority that access did not already have.
func (s *SetupTokens) MintRecovery() string { return s.mint(true) }

func (s *SetupTokens) mint(recovery bool) string {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tok] = setupToken{expires: time.Now().Add(24 * time.Hour), recovery: recovery}
	return tok
}

// Consume validates and burns a token: single-use.
func (s *SetupTokens) Consume(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tok]
	if !ok {
		return false
	}
	delete(s.tokens, tok)
	return time.Now().Before(t.expires)
}

// Valid reports whether a token would be accepted, WITHOUT burning it. A
// ceremony is two requests — begin and finish — and consuming the token on the
// first would guarantee the second failed. Consumption belongs at the end, when
// a passkey actually exists.
func (s *SetupTokens) Valid(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tok]
	return ok && time.Now().Before(t.expires)
}

// ValidRecovery is Valid, restricted to tokens minted by MintRecovery. It is
// what the §8.6 gate consults once a passkey exists.
func (s *SetupTokens) ValidRecovery(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tok]
	return ok && t.recovery && time.Now().Before(t.expires)
}

// HandlerWithAuth builds the internal-surface HTTP handler. Page packages register
// their routes via mount functions so they land INSIDE the CSRF wrap (SPEC §8.3).
// Auth, when supplied, wraps everything in the session gate of SPEC §8.3; a nil
// authDeps (tests) leaves it off. CSRF stays on regardless of binding.
func HandlerWithAuth(st store.Store, setup *SetupTokens, authDeps *AuthDeps, mounts ...func(*http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	for _, m := range mounts {
		m(mux)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})

	// The SPA and its data plane are part of every composition, so a test that
	// builds the handler exercises the same portal an owner gets. Its catch-all
	// runs last in ServeMux precedence: every registered route wins over it.
	mountSPA(mux)
	MountSessionAPI(mux, SessionAPIDeps{Store: st, NeedsSetup: func(ctx context.Context) bool {
		n, err := st.CountCredentialsByKind(ctx, "passkey")
		return err == nil && n == 0
	}})

	// GET /setup serves the SPA shell THROUGH the §8.6 gate: only while zero
	// passkeys exist, and only from loopback or with a valid one-time token.
	// The same rule also guards /setup/begin and /setup/finish server-side
	// (AuthDeps.SetupAllowed) — the page gate is what the spec promises about
	// the wizard being reachable at all, and rendering must not burn the token
	// (a ceremony is several requests; consumption happens on finish).
	mux.HandleFunc("GET /setup", func(w http.ResponseWriter, r *http.Request) {
		gate(st, setup, w, r, func() {
			serveShell(w, r)
		})
	})
	if authDeps != nil {
		MountAuthPages(mux, *authDeps)
	}

	if authDeps == nil {
		mux.HandleFunc("POST /setup", func(w http.ResponseWriter, r *http.Request) {
			gate(st, setup, w, r, func() {
				http.Error(w, "portal authentication is not configured", http.StatusNotImplemented)
			})
		})
	}

	// Account resolution wraps the routes but sits INSIDE csrf and session: it
	// only decides which identity a page is about, and must not run before the
	// checks that decide whether the request is allowed at all.
	var audit func(action, resource, outcome string)
	if authDeps != nil {
		audit = authDeps.audit
	}
	h := csrfMiddleware(accountMiddleware(st, mux, audit), audit)
	if authDeps != nil {
		h = authDeps.SessionMiddleware(h)
	}
	// Outermost, so it applies to error responses and redirects too — a 403 from
	// the csrf check is still a page a browser renders.
	return securityHeaders(h)
}

// portalCSP is every portal response's policy. The web wallet's form page alone widens its
// form-action (wallet_pages.go, walletFormCSP).
const portalCSP = "default-src 'self'; " +
	// The SPA ships no inline script — Vite emits external hashed files —
	// so script-src needs no 'unsafe-inline' any more. Styles keep it:
	// React style props render as style attributes.
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " + // the invite QR is a data: PNG
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// securityHeaders sets what every portal HTML response should have carried and
// did not. The media route set all of this from the start; the pages that render
// contact names, message bodies and filenames — all peer-supplied — set none of
// it.
//
// frame-ancestors is the one that closes a live gap rather than adding depth:
// the portal is a single-click-to-mutate surface (approve a contact, remove one,
// change permissions, rotate a key), and SameSite=Strict on the csrf cookie stops
// cross-site FORM posts but does nothing about the portal being framed and
// clicked through. X-Frame-Options repeats it for browsers that predate CSP 2.
//
// 'unsafe-inline' is honest rather than aspirational: the passkey ceremony and
// the message pages carry inline <script>, and every page carries inline <style>.
// Nonces would be stricter and are worth doing later; the directives that need no
// refactor are worth having now.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", portalCSP)
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// gate enforces the wizard rule (SPEC §8.6): only while ZERO passkeys exist, and only
// from loopback or with a valid one-time token. With passkeys present the wizard is
// gone (404) and outstanding tokens are dead.
func gate(st store.Store, setup *SetupTokens, w http.ResponseWriter, r *http.Request, ok func()) {
	n, err := st.CountCredentialsByKind(r.Context(), "passkey")
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if n > 0 {
		// A passkey exists, so the wizard is closed to everything EXCEPT a
		// recovery token minted over the admin socket (SPEC §3.1, §8.6). Not
		// loopback: once an owner exists, opening the ceremony to every local
		// process would let one register itself as a second owner. Not an
		// ordinary first-run token either — that one died with the first
		// passkey, and honouring a leftover would be the same hole with a
		// longer fuse.
		if tok := r.URL.Query().Get("token"); tok != "" && setup.ValidRecovery(tok) {
			ok()
			return
		}
		http.NotFound(w, r)
		return
	}
	if isLoopbackAddr(r.RemoteAddr) {
		ok()
		return
	}
	// Validate WITHOUT burning. Rendering the wizard is the first of at least
	// three requests — page, /setup/begin, /setup/finish — so consuming here
	// guaranteed the ceremony that follows was refused, and first run over a
	// non-loopback bind could never complete. The token is burned once a passkey
	// actually exists (AuthDeps.SetupDone).
	if tok := r.URL.Query().Get("token"); tok != "" && setup.Valid(tok) {
		ok()
		return
	}
	http.Error(w, "setup requires loopback or a one-time setup token", http.StatusForbidden)
}

func isLoopbackAddr(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// csrfMiddleware refuses a state change a page of another origin could have made, with two checks
// that do not stand in for each other (SPEC §8.3, docs/threat-model.md boundary 2):
//
//   - the double-submit cookie: GETs receive it; every other method echoes it in X-Pact-Csrf or,
//     for an HTML form, the `csrf` field (the first one: the value the page wrote);
//   - where the request came from. The cookie alone is not enough: it is not HttpOnly (the page's
//     script reads it), and cookies are isolated by host, not by port — so a page served on any other
//     port of the same host (another local app, a dev server) reads it and posts it back, and
//     SameSite=Strict does not stop that, because another port is the same SITE. A browser says
//     where a request came from: `Sec-Fetch-Site` must be same-origin (or none, a person's own
//     navigation). A browser that sends no Fetch Metadata still sends Origin on a POST, which must
//     then be this portal's own. `Origin: null` alone decides nothing: the portal's own pages send it
//     under their no-referrer policy, so without Fetch Metadata the cookie is the whole check.
//
// A client that is no browser sends neither header and is judged by the token alone: a forged
// request needs a browser, and a browser says where it was. Each refusal is audited.
func csrfMiddleware(next http.Handler, audit func(action, resource, outcome string)) http.Handler {
	refuse := func(w http.ResponseWriter, r *http.Request, why, msg string) {
		if audit != nil {
			audit("portal_request", "path:"+r.URL.Path, why)
		}
		http.Error(w, msg, http.StatusForbidden)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(csrfCookieName())
		if err != nil || c.Value == "" {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				http.Error(w, "entropy unavailable", http.StatusInternalServerError)
				return
			}
			v := hex.EncodeToString(b)
			http.SetCookie(w, &http.Cookie{
				Name: csrfCookieName(), Value: v, Path: "/",
				HttpOnly: false, SameSite: http.SameSiteStrictMode,
			})
			c = &http.Cookie{Name: csrfCookieName(), Value: v}
			// A handler that renders the token into a form reads it from the request, so the value
			// minted here has to be on the request too: the browser only has it once this response
			// arrives. Without this, a page opened with no cookie yet (a bookmark, a link) rendered
			// an empty token, and its form was refused.
			r = r.Clone(r.Context())
			r.AddCookie(c)
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if !sameOrigin(r) {
				refuse(w, r, "cross_site", "cross-site request refused")
				return
			}
			h := r.Header.Get("X-Pact-Csrf")
			if h == "" {
				// HTML forms cannot set headers: accept the double-submit value
				// as a form field instead (same cookie comparison).
				_ = r.ParseForm()
				h = r.PostForm.Get("csrf")
			}
			if h == "" || subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) != 1 {
				refuse(w, r, "csrf", "csrf token missing or wrong")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether a browser says a state-changing request came from this portal (see
// csrfMiddleware). No header at all is a client that is no browser.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		return o == browserOrigin(r)
	}
	return true
}

// LoadTLS reads the internal surface's certificate and key (SPEC §8.3), once, at startup. Neither
// set is nil: the surface is served over plain HTTP, which the config allows only on a loopback
// bind. One without the other, or a pair that does not load, is an error that names the paths: a
// configuration that promises TLS never falls back to plaintext.
//
// Until 2026-09-27 nothing read these files. The config check (config.go) accepted a non-loopback
// bind once the two PATHS were set, the printed portal URL said https, the session cookie was
// marked Secure, and the listener spoke plain HTTP on every interface.
func LoadTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("internal TLS needs both a certificate and a key (internal_tls_cert %q, internal_tls_key %q)", certFile, keyFile)
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("internal TLS: loading %s and %s: %w", certFile, keyFile, err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

// Serve runs the internal listener until ctx ends (wired by `serve`, SPEC §2.2): over TLS when
// tlsConfig is set (LoadTLS), over plain HTTP when it is nil.
func Serve(ctx context.Context, bind string, tlsConfig *tls.Config, h http.Handler) error {
	srv := &http.Server{
		Addr: bind, Handler: h,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}
	errc := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			errc <- srv.ListenAndServeTLS("", "")
			return
		}
		errc <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		if err != nil && !strings.Contains(err.Error(), "Server closed") {
			return err
		}
		return nil
	}
}

// randomHex8 is a tiny helper for UI-minted idempotency keys.
func randomHex8() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// nowUnix is a seam for page handlers needing wall-clock seconds.
var nowUnix = func() int64 { return time.Now().Unix() }

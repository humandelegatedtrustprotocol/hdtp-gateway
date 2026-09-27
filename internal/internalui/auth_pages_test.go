package internalui

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/pact-cloud/pact-gateway/web"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

const (
	portalRPID   = "localhost"
	portalOrigin = "http://localhost:8080"
)

type portalEnv struct {
	// handle is the WebAuthn user id the last registration offered.
	handle string
	h      http.Handler
	st     store.Store
	setup  *SetupTokens
	rp     virtualwebauthn.RelyingParty
	authn  virtualwebauthn.Authenticator
	rows   []string
}

func newPortalEnv(t *testing.T) *portalEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e := &portalEnv{
		st: st, setup: NewSetupTokens(),
		rp:    virtualwebauthn.RelyingParty{Name: "pact-gateway", ID: portalRPID, Origin: portalOrigin},
		authn: virtualwebauthn.NewAuthenticator(),
	}
	deps := &AuthDeps{
		Service: auth.New(st),
		Origin:  OriginPolicy{InternalHost: ""},
		Audit:   func(a, r, o string) { e.rows = append(e.rows, a+" "+r+" "+o) },
		// Mirrors production (cli.go): open while unclaimed, and afterwards only
		// to a recovery token minted by `passkey reset-wizard` (§8.6).
		SetupAllowed: func(r *http.Request) bool {
			n, err := st.CountCredentialsByKind(r.Context(), "passkey")
			if err != nil {
				return false
			}
			if n > 0 {
				return e.setup.ValidRecovery(r.URL.Query().Get("token"))
			}
			return true
		},
		SetupDone: func(r *http.Request) { e.setup.Consume(r.URL.Query().Get("token")) },
	}
	e.h = HandlerWithAuth(st, e.setup, deps)
	return e
}

// do issues a request carrying the CSRF cookie/header pair and any session.
func (e *portalEnv) do(t *testing.T, method, path string, body []byte, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body == nil {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Host = "localhost:8080"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "pact_csrf", Value: "tok"})
	req.Header.Set("X-Pact-Csrf", "tok")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// AC (P7-03a): a passkey can actually be registered and used through the portal.
// The previous fixed relying party (RP ID `localhost` with a 127.0.0.1 origin)
// could never complete a ceremony, which is why POST /setup returned 501.
func TestPortalRegistrationAndLoginCeremony(t *testing.T) {
	e := newPortalEnv(t)

	// --- registration ---
	rec := e.do(t, "POST", "/setup/begin", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("setup/begin: %d %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(begin.Options))
	if err != nil {
		t.Fatalf("the options the portal issued are not usable: %v", err)
	}
	e.handle = parsed.UserID // what the authenticator will replay at login
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	att := virtualwebauthn.CreateAttestationResponse(e.rp, e.authn, cred, *parsed)
	rec = e.do(t, "POST", "/setup/finish?ceremony="+begin.Ceremony+"&tag=laptop", []byte(att), nil)
	if rec.Code != 200 {
		t.Fatalf("setup/finish: %d %s", rec.Code, rec.Body.String())
	}
	e.authn.AddCredential(cred)

	n, err := e.st.CountCredentialsByKind(context.Background(), "passkey")
	if err != nil || n != 1 {
		t.Fatalf("the passkey was not stored: %d %v", n, err)
	}
	// setup closes once a passkey exists
	if rec := e.do(t, "POST", "/setup/begin", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("setup stayed open after the first passkey: %d", rec.Code)
	}

	// --- login ---
	rec = e.do(t, "POST", "/login/begin", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("login/begin: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	aopts, err := virtualwebauthn.ParseAssertionOptions(string(begin.Options))
	if err != nil {
		t.Fatal(err)
	}
	// Replay the handle REGISTRATION offered, not the owner id read back out of
	// the store. This line used to do the latter, and it is why a passkey that
	// could never log in from a browser looked fine here for weeks: it
	// manufactured the value the product was supposed to have written, so a
	// product that wrote a placeholder still passed.
	e.authn.Options.UserHandle = []byte(e.handle)
	assertion := virtualwebauthn.CreateAssertionResponse(e.rp, e.authn, e.authn.Credentials[0], *aopts)
	rec = e.do(t, "POST", "/login/finish?ceremony="+begin.Ceremony, []byte(assertion), nil)
	if rec.Code != 200 {
		t.Fatalf("login/finish: %d %s", rec.Code, rec.Body.String())
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName() {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("login produced no session cookie")
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("the session cookie is not the inverse of the CSRF one: %+v", session)
	}

	// --- the gate ---
	// The SPA shell is static code and serves to anyone, like the login page
	// always did; what authentication protects is the DATA plane and every
	// mutation. So the boundary to assert is /api and POST, not the shell.
	if rec := e.do(t, "GET", "/api/contacts", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated request read portal data: %d", rec.Code)
	}
	if rec := e.do(t, "POST", "/contacts/add", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated mutation was not refused: %d", rec.Code)
	}
	if rec := e.do(t, "GET", "/api/session", nil, []*http.Cookie{session}); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"signed_in":true`) {
		t.Fatalf("a signed-in request was refused: %d %s", rec.Code, rec.Body.String())
	}

	// --- logout ---
	rec = e.do(t, "POST", "/logout", nil, []*http.Cookie{session})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := e.do(t, "GET", "/api/contacts", nil, []*http.Cookie{session}); rec.Code != http.StatusUnauthorized {
		t.Fatal("the session survived logout")
	}
}

// AC (P7-03a): a loopback portal has no login (SPEC §8.3), and Host is not
// trusted — a spoofed one must not bind a credential to a domain the owner does
// not control.
func TestLoopbackStillDemandsALoginAndHostIsNotTrusted(t *testing.T) {
	e := newPortalEnv(t)
	// SPEC §8.3: a session on EVERY bind. Loopback used to be a carve-out — it
	// served the whole portal with no login — which made a registered passkey
	// optional in practice and treated "can open a local socket" as identity.
	// The shell is static code and still serves (it IS the sign-in page); the
	// data behind it must not.
	if rec := e.do(t, "GET", "/api/contacts", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a loopback portal served data with no session: %d", rec.Code)
	}
	if rec := e.do(t, "POST", "/contacts/add", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a loopback portal accepted an unauthenticated mutation: %d", rec.Code)
	}

	// a spoofed Host is refused rather than used as the relying party
	req := httptest.NewRequest("POST", "/setup/begin", bytes.NewReader(nil))
	req.Host = "attacker.example.com"
	req.AddCookie(&http.Cookie{Name: "pact_csrf", Value: "tok"})
	req.Header.Set("X-Pact-Csrf", "tok")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a spoofed Host was accepted as the relying party: %d %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, row := range e.rows {
		if strings.Contains(row, "refused_origin") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the refusal was not audited: %v", e.rows)
	}
}

// AC (P10-05a): the portal actually serves a registration ceremony.
//
// The server-rendered wizard once shipped prose saying "Passkey registration
// arrives with phase P2" and no JavaScript at all — the ceremonies worked and
// nothing in a browser ever called them. The portal is an embedded SPA now, so
// the property is checked where it lives: the compiled bundle must carry the
// WebAuthn ceremonies, driven against the real endpoints. A bundle without them
// is that same defect shipped a second way.
func TestEmbeddedBundleCarriesTheCeremonies(t *testing.T) {
	var all strings.Builder
	err := fs.WalkDir(web.Dist, "dist", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		b, rerr := fs.ReadFile(web.Dist, p)
		if rerr != nil {
			return rerr
		}
		all.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	js := all.String()
	if js == "" {
		t.Fatal("no JavaScript in the embedded dist — the portal is an empty shell; run `make web`")
	}
	for _, want := range []string{
		"navigator.credentials.create", // registration (the wizard)
		"navigator.credentials.get",    // sign-in
		"/setup/begin", "/setup/finish",
		"/login/begin", "/login/finish",
		"X-Pact-Csrf",
		"attestationObject",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the embedded portal bundle does not contain %q — it cannot drive that ceremony", want)
		}
	}
}

// AC (P10-05b): rendering the wizard must not burn the one-time token.
//
// A ceremony is at least three requests — the page, /setup/begin, /setup/finish
// — and the gate consumed the token on the first. So an owner following the
// setup link printed in the logs got the page once and was then refused, making
// first run over a non-loopback bind impossible.
func TestSetupTokenSurvivesRenderingTheWizard(t *testing.T) {
	setup := NewSetupTokens()
	tok := setup.Mint()

	if !setup.Valid(tok) {
		t.Fatal("a freshly minted token is not valid")
	}
	// Whatever the page render does, the token must still open the ceremony.
	for i := 0; i < 3; i++ {
		if !setup.Valid(tok) {
			t.Fatalf("the token stopped being valid after %d checks", i)
		}
	}
	// Only completing setup burns it.
	if !setup.Consume(tok) {
		t.Fatal("consuming a valid token failed")
	}
	if setup.Valid(tok) {
		t.Fatal("the token survived being consumed — it is not single-use")
	}
}

// registerPasskey runs one full WebAuthn registration through the portal and
// reports the HTTP status of the /setup/begin that opened it — which is where
// the §8.6 gate answers.
func (e *portalEnv) registerPasskey(t *testing.T, query, tag string) int {
	t.Helper()
	rec := e.do(t, "POST", "/setup/begin"+query, nil, nil)
	if rec.Code != 200 {
		return rec.Code
	}
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	parsed, err := virtualwebauthn.ParseAttestationOptions(string(begin.Options))
	if err != nil {
		t.Fatal(err)
	}
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	// What the node handed the authenticator as the WebAuthn user id. A real
	// authenticator stores this with the credential and replays it on every
	// login, so the test must too — reading the owner id out of the store
	// instead would manufacture the value the product is supposed to have put
	// here, and hide it when the product puts something else.
	e.handle = parsed.UserID
	att := virtualwebauthn.CreateAttestationResponse(e.rp, e.authn, cred, *parsed)
	sep := "?"
	if query != "" {
		sep = "&"
	}
	fin := e.do(t, "POST", "/setup/finish"+query+sep+"ceremony="+begin.Ceremony+"&tag="+tag, []byte(att), nil)
	if fin.Code != 200 {
		t.Fatalf("registration finished %d: %s", fin.Code, fin.Body.String())
	}
	e.authn.AddCredential(cred)
	return 200
}

// Losing every passkey must not mean losing the node.
//
// With §8.3 requiring a session on every bind, the loopback carve-out is gone —
// and it was the only thing that made a lost passkey survivable. So the CLI's
// documented recovery (`passkey reset-wizard`, over the admin unix socket) has
// to actually work, and until this change it could not: it minted an ordinary
// token, and the wizard refused every token once a passkey existed. It handed
// out a URL guaranteed to fail.
func TestALockedOutOwnerCanRecoverWithAMintedToken(t *testing.T) {
	e := newPortalEnv(t)
	ctx := context.Background()

	// First run: the node is claimed.
	if code := e.registerPasskey(t, "", "first"); code != 200 {
		t.Fatalf("first registration: %d", code)
	}
	if n, _ := e.st.CountCredentialsByKind(ctx, "passkey"); n != 1 {
		t.Fatalf("passkeys after first run: %d", n)
	}

	// The wizard is closed — to bare loopback, and to an ordinary token, which
	// is what a leftover first-run link is. Honouring either would let anyone
	// who can reach the portal register themselves as an owner.
	if code := e.registerPasskey(t, "", "sneak"); code == 200 {
		t.Fatal("the wizard re-opened with no token once a passkey existed")
	}
	ordinary := e.setup.Mint()
	if code := e.registerPasskey(t, "?token="+ordinary, "sneak"); code == 200 {
		t.Fatal("an ordinary setup token re-opened the wizard after the first passkey")
	}

	// The PAGE gate must agree with the ceremony gate. They are two separate
	// implementations of one rule — internalui.gate for GET /setup, AuthDeps
	// .SetupAllowed for the ceremonies — so each is checked, or they drift and
	// the wizard renders for someone who cannot finish it (or worse, the
	// reverse).
	if rec := e.do(t, "GET", "/setup", nil, nil); rec.Code == 200 {
		t.Error("the wizard PAGE served with no token once a passkey existed")
	}
	if rec := e.do(t, "GET", "/setup?token="+ordinary, nil, nil); rec.Code == 200 {
		t.Error("the wizard PAGE served to an ordinary token after the first passkey")
	}

	// `passkey reset-wizard` mints the one token that does.
	recovery := e.setup.MintRecovery()
	if rec := e.do(t, "GET", "/setup?token="+recovery, nil, nil); rec.Code != 200 {
		t.Errorf("the wizard PAGE refused a recovery token: %d", rec.Code)
	}
	if code := e.registerPasskey(t, "?token="+recovery, "replacement"); code != 200 {
		t.Fatalf("a recovery token did not re-open the wizard: %d", code)
	}
	// It ADDS a way in; it never removes the ones already there.
	if n, _ := e.st.CountCredentialsByKind(ctx, "passkey"); n != 2 {
		t.Fatalf("passkeys after recovery: %d, want 2", n)
	}

	// And it is single-use: the link cannot be replayed by whoever sees it next.
	if code := e.registerPasskey(t, "?token="+recovery, "replay"); code == 200 {
		t.Fatal("a recovery token worked twice")
	}
}

// Sign out, sign back in. Reported from a real browser: registration worked, the
// session it minted worked, and the passkey could never log in afterwards.
//
// TestPortalRegistrationAndLoginCeremony did not catch it because its login half
// overwrites the authenticator's user handle with the owner id read out of the
// store — manufacturing the very value the product is supposed to have put
// there. A real authenticator returns whatever it was handed at registration,
// and nothing here may pretend otherwise.
func TestAPasskeyCanLogInAgainAfterSigningOut(t *testing.T) {
	e := newPortalEnv(t)

	// Register exactly as the wizard does.
	if code := e.registerPasskey(t, "", "laptop"); code != 200 {
		t.Fatalf("registration: %d", code)
	}

	// Now sign in with it — WITHOUT touching the authenticator's user handle.
	// Whatever registration bound to this credential is what a browser will
	// return, so it is what the node must be able to resolve.
	rec := e.do(t, "POST", "/login/begin", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("login/begin: %d %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		Ceremony string          `json:"ceremony"`
		Options  json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	aopts, err := virtualwebauthn.ParseAssertionOptions(string(begin.Options))
	if err != nil {
		t.Fatal(err)
	}
	// Replay exactly what registration bound to this credential.
	e.authn.Options.UserHandle = []byte(e.handle)
	assertion := virtualwebauthn.CreateAssertionResponse(e.rp, e.authn, e.authn.Credentials[0], *aopts)
	rec = e.do(t, "POST", "/login/finish?ceremony="+begin.Ceremony, []byte(assertion), nil)
	if rec.Code != 200 {
		t.Fatalf("a registered passkey could not sign in: %d %s\n"+
			"The credential's user handle is what the authenticator replays; if "+
			"registration bound a placeholder there, no browser can ever log in.",
			rec.Code, rec.Body.String())
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName() {
			session = c
		}
	}
	if session == nil || session.Value == "" {
		t.Fatal("login produced no session cookie")
	}
	if rec := e.do(t, "GET", "/api/session", nil, []*http.Cookie{session}); !strings.Contains(rec.Body.String(), `"signed_in":true`) {
		t.Fatalf("the session from a second login does not work: %s", rec.Body.String())
	}
}

// The sign-in page asks for its own fonts and brand mark before anyone has
// signed in. Auditing each of those as a refused request buried the real
// refusals: a live node had 39 of them in its newest 400 rows, every one
// counted as a refusal by the audit view's filter.
func TestStaticShellIsNotAuditedAsARefusal(t *testing.T) {
	e := newPortalEnv(t)
	for _, path := range []string{"/fonts/inter-latin-wght.woff2", "/brand/favicon.svg", "/assets/index-abc123.js"} {
		e.rows = nil
		e.do(t, http.MethodGet, path, nil, nil)
		for _, r := range e.rows {
			if strings.Contains(r, "identity_required") {
				t.Errorf("%s was audited as a refusal: %s", path, r)
			}
		}
	}
	// A real page still is one: the shell exemption must not become a hole.
	e.rows = nil
	e.do(t, http.MethodGet, "/api/contacts", nil, nil)
	var refused bool
	for _, r := range e.rows {
		if strings.Contains(r, "identity_required") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("an unauthenticated API request was not audited: %v", e.rows)
	}
}

package internalui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

type env struct {
	h  http.Handler
	st *store.SQLite
	tk *SetupTokens
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	tk := NewSetupTokens()
	return &env{h: HandlerWithAuth(st, tk, nil), st: st, tk: tk}
}

// get performs a request with a controllable remote address.
func get(t *testing.T, h http.Handler, path, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = remote
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// /healthz says ok while what the node serves through answers, and 503 with the reason when it
// does not (today the limits sidecar, SPEC §5.7): the container HEALTHCHECK reads the status.
func TestHealthz(t *testing.T) {
	var down error
	h := Health(func(context.Context) error { return down })
	rr := get(t, h, "/healthz", "127.0.0.1:5555")
	if rr.Code != 200 || rr.Body.String() != "ok\n" {
		t.Fatalf("healthz: %d %q", rr.Code, rr.Body.String())
	}
	down = errors.New("the limits sidecar at /data/limits.sock is not answering")
	rr = get(t, h, "/healthz", "127.0.0.1:5555")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "limits sidecar") {
		t.Fatalf("healthz with the sidecar down: %d %q, want 503 naming it", rr.Code, rr.Body.String())
	}
	// The portal's handler no longer answers it: one health check, where serve mounts it.
	if rr := get(t, newEnv(t).h, "/healthz", "127.0.0.1:5555"); strings.HasPrefix(rr.Body.String(), "ok") {
		t.Fatalf("the portal's own handler still answers /healthz: %q", rr.Body.String())
	}
}

func TestShellPageServedAndSelfContained(t *testing.T) {
	e := newEnv(t)
	rr := get(t, e.h, "/", "127.0.0.1:5555")
	if rr.Code != 200 {
		t.Fatalf("shell: %d", rr.Code)
	}
	body := rr.Body.String()
	for _, bad := range []string{`src="http`, `href="http`, `src='http`, `href='http`} {
		if strings.Contains(body, bad) {
			t.Fatalf("external asset reference found: %s", bad)
		}
	}
}

func TestWizardLoopbackZeroPasskeys(t *testing.T) {
	e := newEnv(t)
	rr := get(t, e.h, "/setup", "127.0.0.1:9999")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "/assets/") {
		t.Fatalf("wizard from loopback at zero passkeys: %d", rr.Code)
	}
}

func TestWizardNonLoopbackNeedsToken(t *testing.T) {
	e := newEnv(t)
	if rr := get(t, e.h, "/setup", "10.0.0.9:9999"); rr.Code != http.StatusForbidden {
		t.Fatalf("non-loopback without token: %d, want 403", rr.Code)
	}
	tok := e.tk.Mint()
	if rr := get(t, e.h, "/setup?token="+tok, "10.0.0.9:9999"); rr.Code != 200 {
		t.Fatalf("non-loopback with token: %d, want 200", rr.Code)
	}
	// Rendering the page must NOT burn the token: a ceremony is several requests
	// (page, /setup/begin, /setup/finish) and a reload is normal. SPEC §8.3 ties
	// invalidation to registration — the token "is invalidated the moment any
	// passkey is registered" — not to having been looked at (P10-05b).
	if rr := get(t, e.h, "/setup?token="+tok, "10.0.0.9:9999"); rr.Code != 200 {
		t.Fatalf("reloading the wizard burned the token: %d", rr.Code)
	}
	// A token that was never minted is still refused.
	if rr := get(t, e.h, "/setup?token=deadbeef", "10.0.0.9:9999"); rr.Code != http.StatusForbidden {
		t.Fatal("an unknown token was accepted")
	}
	// And completing setup burns it: single-use, as §8.3 requires.
	if !e.tk.Consume(tok) {
		t.Fatal("consuming a valid token failed")
	}
	if rr := get(t, e.h, "/setup?token="+tok, "10.0.0.9:9999"); rr.Code != http.StatusForbidden {
		t.Fatal("the token survived registration — it is not single-use")
	}
}

func TestWizardGoneOncePasskeyExists(t *testing.T) {
	e := newEnv(t)
	if err := e.st.InsertCredential(context.Background(), store.Credential{
		OwnerID: mustOwner(t, e.st), Kind: "passkey", Tag: "phone", Data: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	// even from loopback, the wizard is gone; and minted tokens are invalidated
	tok := e.tk.Mint()
	if rr := get(t, e.h, "/setup", "127.0.0.1:1"); rr.Code != http.StatusNotFound {
		t.Fatalf("wizard with passkeys from loopback: %d, want 404", rr.Code)
	}
	if rr := get(t, e.h, "/setup?token="+tok, "10.0.0.9:1"); rr.Code != http.StatusNotFound {
		t.Fatalf("wizard with passkeys via token: %d, want 404", rr.Code)
	}
}

func TestCSRFCookieOnGETAndEnforcedOnPOST(t *testing.T) {
	e := newEnv(t)
	rr := get(t, e.h, "/", "127.0.0.1:1")
	var csrf string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "hdtp_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("no CSRF cookie set on GET")
	}
	// POST without header → 403
	req := httptest.NewRequest("POST", "/setup", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: csrf})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF header: %d, want 403", rec.Code)
	}
	// POST with matching header passes CSRF (may fail later for other reasons, but not 403-csrf)
	req2 := httptest.NewRequest("POST", "/setup", nil)
	req2.RemoteAddr = "127.0.0.1:1"
	req2.AddCookie(&http.Cookie{Name: "hdtp_csrf", Value: csrf})
	req2.Header.Set("X-HDTP-Csrf", csrf)
	rec2 := httptest.NewRecorder()
	e.h.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusForbidden && strings.Contains(rec2.Body.String(), "csrf") {
		t.Fatalf("POST with CSRF header still refused: %d %s", rec2.Code, rec2.Body.String())
	}
}

func mustOwner(t *testing.T, st *store.SQLite) string {
	t.Helper()
	o, err := st.CreateOwnerWithID(context.Background(), "", "O")
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

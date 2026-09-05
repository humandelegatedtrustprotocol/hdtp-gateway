package internalui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The portal renders contact display names, message bodies, topics and filenames
// — every one of them chosen by a peer. It shipped with none of the headers that
// bound what a browser will do with that, while the media route (added later) set
// all of them. These are checked on the assembled handler rather than on the
// middleware, because a header set by a middleware nobody wired in is not set.
func TestPortalResponsesCarrySecurityHeaders(t *testing.T) {
	h := newEnv(t).h

	for _, path := range []string{"/", "/contacts", "/nope-does-not-exist"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			csp := rec.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Fatal("no Content-Security-Policy")
			}
			// The clickjacking pair. The portal mutates state on one click —
			// approve a contact, remove one, rotate a key — and SameSite=Strict
			// stops cross-site form posts, not being framed and clicked through.
			if !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("CSP does not forbid framing: %q", csp)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := rec.Header().Get("Referrer-Policy"); got == "" {
				t.Error("no Referrer-Policy: portal URLs carry account and contact identifiers")
			}
			// The QR on the invite page is a data: PNG, and every page styles
			// itself inline; a policy that breaks them would be reverted, so it
			// is pinned here as a deliberate allowance.
			if !strings.Contains(csp, "img-src 'self' data:") {
				t.Errorf("CSP would break the invite QR: %q", csp)
			}
		})
	}
}

// Headers must survive the error paths too — a 403 from the csrf check is still
// a document a browser renders.
func TestSecurityHeadersSurviveARefusal(t *testing.T) {
	h := newEnv(t).h
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/contacts", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected the csrf refusal, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("a refused request answered without a CSP")
	}
}

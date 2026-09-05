package internalui

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// AC (P10-05d): at zero passkeys the portal root IS the wizard, not a link to
// it. SPEC §8.3 says the portal "auto-shows the wizard"; it used to render a
// shell whose only affordance was a hyperlink, so an owner who did not click it
// left the node unclaimed — and an unclaimed node is claimable by whoever
// reaches it next.
func TestPortalRootAutoShowsTheWizardAtZeroPasskeys(t *testing.T) {
	// §8.3: with zero passkeys the portal leads to the wizard and nowhere else.
	// The SPA routes on /api/session's needs_setup, so THAT is the load-bearing
	// signal now; the ceremony itself and its bundle presence are held by
	// TestEmbeddedBundleCarriesTheCeremonies, and the gate that keeps a stranger
	// from registering guards /setup/begin server-side (SetupAllowed), asserted
	// in TestPortalRegistrationAndLoginCeremony when setup closes.
	e := newEnv(t)
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/session", nil))
	if rr.Code != 200 {
		t.Fatalf("session at zero passkeys: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"needs_setup":true`) {
		t.Fatalf("the portal does not lead to the wizard at zero passkeys: %s", rr.Body.String())
	}
	// The wizard view must have shipped, or the routing above lands on nothing.
	if !strings.Contains(bundleJS(t), "Register a passkey") {
		t.Error("the compiled portal has no wizard view")
	}
}

func firstN(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

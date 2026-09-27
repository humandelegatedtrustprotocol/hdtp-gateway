package node

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/internalui"
)

// testLanding is the landing page `serve` injects (cli's landingPage): the portal's, over what the
// node supplies. The node's tests serve the same page the shipped binary does.
func testLanding(d LandingDeps) http.Handler {
	return internalui.LandingHandler(internalui.LandingDeps(d))
}

// The landing page is injected so that the node does not import the portal, and a node built
// without one would register a nil handler for /i/{token}. New refuses it instead, and says why.
func TestNewRefusesANodeWithNoLandingPage(t *testing.T) {
	e, _ := newEnv(t)
	o := e.options()
	o.Landing = nil
	if _, err := New(context.Background(), o); err == nil || !strings.Contains(err.Error(), "landing") {
		t.Fatalf("a node with no invite landing page was built (err=%v)", err)
	}
}

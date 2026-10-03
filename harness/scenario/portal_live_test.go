package scenario

import (
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/images"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/portal"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/registry"
)

// S11 — every portal page, in a real browser, in both themes.
//
// docs/conformance.md lists "browser rendering" as uncovered: pages are asserted
// as HTML, never rendered. That gap hid a real one — six of the nine standalone
// pages had no prefers-color-scheme block, so on a dark desktop they rendered
// black-on-white while the rest of the portal followed the system. No HTML
// assertion could have caught it, and no unit test did.
func TestEveryPortalPageRendersInBothThemes(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S11", Name: "every portal page renders in both themes with no console error", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 12 * time.Minute,
	})

	p, err := w.Paired(ctx, images.Node)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// A browser that is the OWNER: the portal requires a session on every bind (SPEC §8.3), so
	// an anonymous one is shown the sign-in view at every path and this would screenshot that
	// ten times over, in both themes, and pass.
	br, err := p.Portal.Browser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()

	base := p.Portal.Base
	// The owner-facing surface. Each is a page a person actually opens.
	pages := []struct{ name, path string }{
		{"dashboard", "/"},
		{"inbox", "/inbox?account=" + p.AccountID},
		{"contacts", "/contacts?account=" + p.AccountID},
		{"invites", "/invites?account=" + p.AccountID},
		{"requests", "/requests?account=" + p.AccountID},
		{"card", "/card?account=" + p.AccountID},
		{"identity", "/identity"},
		{"settings", "/settings"},
		{"integrations", "/integrations?account=" + p.AccountID},
		{"audit", "/audit"},
	}

	// Before rendering anything: can a person REACH these pages by clicking?
	// Every URL below is constructed by this test, which is how the portal shipped
	// with a dashboard whose links carried no account — each one landing on a page
	// that 404'd, 400'd, or rendered blank. A test that builds its own URLs proves
	// the pages render and nothing about whether they can be found.
	home, err := br.Rendered(ctx, base+"/")
	if err != nil {
		t.Fatal(err)
	}
	for _, href := range portalLinks(t, home) {
		pg, err := br.Rendered(ctx, base+href)
		if err != nil {
			t.Errorf("the dashboard links to %s and it does not draw: %v", href, err)
			continue
		}
		if strings.Contains(pg.Text, "Nothing lives at") {
			t.Errorf("the dashboard links to %s and nothing lives there — the portal cannot "+
				"be used by clicking", href)
		}
	}

	artifacts := os.Getenv("HDTP_HARNESS_ARTIFACTS")
	var failures []string
	for _, pg := range pages {
		shots := map[portal.Theme][]byte{}
		for _, theme := range []portal.Theme{portal.Light, portal.Dark} {
			v, cerr := br.Capture(ctx, base+pg.path, theme)
			shots[theme] = v.Screenshot
			if artifacts != "" {
				_ = v.SaveScreenshot(artifacts, pg.name+"-"+string(theme))
			}
			if cerr != nil {
				failures = append(failures, pg.name+" ("+string(theme)+"): "+cerr.Error())
				continue
			}
			if len(v.Screenshot) == 0 {
				failures = append(failures, pg.name+" ("+string(theme)+"): rendered nothing")
			}
			// A page that throws in the browser is broken even if its HTML parses.
			if len(v.ConsoleErr) > 0 {
				failures = append(failures, pg.name+" ("+string(theme)+"): console: "+
					strings.Join(v.ConsoleErr, "; "))
			}
		}
		// The assertion that actually catches an unthemed page. A page missing its
		// prefers-color-scheme block renders IDENTICALLY under both emulated
		// schemes — byte-for-byte — while a themed one cannot. No HTML assertion
		// can see this, which is why six of the portal's standalone pages shipped
		// without a dark palette.
		if l, d := shots[portal.Light], shots[portal.Dark]; len(l) > 0 && len(d) > 0 {
			if sha256.Sum256(l) == sha256.Sum256(d) {
				failures = append(failures, pg.name+
					": renders identically in light and dark — it has no theme")
			}
		}
	}
	if len(failures) > 0 {
		t.Fatalf("portal pages failed to render cleanly:\n  %s", strings.Join(failures, "\n  "))
	}
	t.Logf("rendered %d pages x 2 themes with no console errors", len(pages))
}

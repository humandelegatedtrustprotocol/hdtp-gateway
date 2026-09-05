package scenario

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/portal"
)

// S11 — every portal page, in a real browser, in both themes.
//
// docs/conformance.md lists "browser rendering" as uncovered: pages are asserted
// as HTML, never rendered. That gap hid a real one — six of the nine standalone
// pages had no prefers-color-scheme block, so on a dark desktop they rendered
// black-on-white while the rest of the portal followed the system. No HTML
// assertion could have caught it, and no unit test did.
func TestEveryPortalPageRendersInBothThemes(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	p, err := SetupPaired(ctx, "pactui", Ports{Owner: "18651", Public: "18652"}, nodeImage)
	t.Cleanup(func() { p.Teardown("") })
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	br, err := portal.Open(ctx)
	if err != nil {
		t.Fatalf("chrome: %v", err)
	}
	defer br.Close()

	base := "http://localhost:" + p.OwnerPort
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
	for _, href := range dashboardLinks(ctx, t, base) {
		code, body := httpGet(ctx, t, base+href)
		if code == 404 || code == 400 {
			t.Errorf("the dashboard links to %s and it answers %d — the portal cannot "+
				"be used by clicking: %s", href, code, shorten(body, 200))
		}
	}

	artifacts := os.Getenv("PACT_HARNESS_ARTIFACTS")
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

// dashboardLinks returns the in-portal links the dashboard actually offers.
func dashboardLinks(ctx context.Context, t *testing.T, base string) []string {
	t.Helper()
	code, body := httpGet(ctx, t, base+"/")
	if code != 200 {
		t.Fatalf("dashboard: HTTP %d", code)
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(body, `href="`)[1:] {
		i := strings.IndexByte(part, '"')
		if i <= 0 {
			continue
		}
		href := part[:i]
		// in-portal pages only: not the .vcf download, not an external link
		if !strings.HasPrefix(href, "/") || strings.Contains(href, ".vcf") || seen[href] {
			continue
		}
		seen[href] = true
		out = append(out, href)
	}
	if len(out) < 5 {
		t.Fatalf("only %d links on the dashboard; the page is not what we think it is", len(out))
	}
	return out
}

func httpGet(ctx context.Context, t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, string(b)
}

package internalui

// Every standalone portal page must follow the viewer's theme.
//
// Two did not. The inbox rendered black-on-white on a dark desktop while the rest
// of the portal followed the system, and Settings · identity — added later —
// hardcoded light card borders onto whatever ground the browser chose. Both were
// invisible to the existing tests, which assert HTML rather than appearance.
//
// This is the cheap half of that gap: a page that writes its own <html> must
// reach the shared palette. The expensive half (does it actually LOOK right) is
// the harness's screenshot suite.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEveryStandalonePortalPageIsThemed(t *testing.T) {
	files, err := filepath.Glob("*_pages.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no page files found: %v", err)
	}
	doctype := regexp.MustCompile(`(?i)<!doctype html>`)

	checked := 0
	for _, f := range files {
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatal(rerr)
		}
		src := string(b)
		if !doctype.MatchString(src) {
			continue // a fragment inherits the layout's theme
		}
		checked++
		// Either it uses the shared stylesheet, or it carries its own dark block.
		// Both are acceptable; neither is not.
		if strings.Contains(src, "portalStyle") {
			continue
		}
		if strings.Contains(src, "prefers-color-scheme") {
			continue
		}
		t.Errorf("%s renders a full document but neither uses portalStyle nor declares a "+
			"prefers-color-scheme block — on a dark desktop it will render against the "+
			"wrong ground while the rest of the portal follows the system", f)
	}
	if checked == 0 {
		t.Fatal("no standalone pages were checked — the scan is broken, not the pages")
	}
	t.Logf("checked %d standalone portal page(s)", checked)
}

// The shared palette must define both halves. A token defined only inside the
// media query is the classic unreadable-page bug: it never applies in light
// mode. The palette lives in the SPA's stylesheet now; the property is the same.
func TestPortalStyleDefinesBothThemes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	if !strings.Contains(css, ":root {") {
		t.Fatal("style.css has no base :root palette, so light mode has no tokens")
	}
	if !strings.Contains(css, "prefers-color-scheme: dark") {
		t.Fatal("style.css has no dark block")
	}
	base := css[strings.Index(css, ":root {"):strings.Index(css, "@media")]
	dark := css[strings.Index(css, "@media"):]
	for _, tok := range []string{"--ink", "--bg", "--accent", "--line", "--soft",
		"--warn-bg", "--ok-bg", "--err-bg"} {
		if !strings.Contains(base, tok) {
			t.Errorf("%s is not defined in the light palette", tok)
		}
		if !strings.Contains(dark, tok) {
			t.Errorf("%s is not redefined for dark, so it keeps its light value", tok)
		}
	}
	// body must paint its own background: a transparent body borrows whatever the
	// browser chose, which is exactly how a themed page still ends up unreadable.
	if !strings.Contains(css, "background: var(--bg)") {
		t.Error("body does not paint an explicit background from the palette")
	}
}

// The wizard's tag once reached the store double-encoded: the JS ran
// encodeURIComponent and then handed the result to URLSearchParams.set, which
// percent-encodes again. The ceremony lives in web/src/webauthn.ts now; the
// same mistake there would ship the same bug.
func TestWizardDoesNotDoubleEncodeTheTag(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "webauthn.ts"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if strings.Contains(src, "encodeURIComponent(tag") {
		t.Error("the tag is encodeURIComponent'd before URLSearchParams.set, which encodes " +
			"it again — the owner sees their own tag percent-escaped")
	}
	if !strings.Contains(src, `q.set("tag", tag`) {
		t.Error("the tag no longer goes through URLSearchParams.set; re-check the encoding")
	}
}

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
// mode. The palette lives in the SPA's brand layer (web/src/brand.css, loaded
// before style.css); the property is the same.
func TestPortalStyleDefinesBothThemes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "brand.css"))
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	if !strings.Contains(css, ":root {") {
		t.Fatal("brand.css has no base :root palette, so light mode has no tokens")
	}
	if !strings.Contains(css, "prefers-color-scheme: dark") {
		t.Fatal("brand.css has no dark block")
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
	layout, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(layout), "background: var(--bg)") {
		t.Error("body does not paint an explicit background from the palette")
	}
}

// paletteOf reads `--name:value` pairs out of one CSS block.
func paletteOf(block string) map[string]string {
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`--([\w-]+)\s*:\s*([^;}]+)`).FindAllStringSubmatch(block, -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}
	return out
}

// The server-rendered pages (style.go) carry the SPA's palette inline, because they cannot load the
// SPA's stylesheet. Two copies of one palette drift the day they are written, so every token the
// pages use is held to web/src/brand.css's value, light and dark.
func TestServerPagesCarryTheBrandPalette(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "brand.css"))
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	light := regexp.MustCompile(`/\* palette:light \*/\s*:root\s*\{([^}]*)\}`).FindStringSubmatch(css)
	dark := regexp.MustCompile(`/\* palette:dark \*/\s*@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}`).FindStringSubmatch(css)
	if light == nil || dark == nil {
		t.Fatal("brand.css has lost its palette:light or palette:dark block")
	}
	wantLight, wantDark := paletteOf(light[1]), paletteOf(dark[1])
	at := strings.Index(brandPalette, "@media")
	gotLight, gotDark := paletteOf(brandPalette[:at]), paletteOf(brandPalette[at:])
	if len(gotLight) < 10 || len(gotDark) < 10 {
		t.Fatalf("brandPalette parsed to %d light and %d dark tokens; the scan is broken", len(gotLight), len(gotDark))
	}
	for tok, v := range gotLight {
		if wantLight[tok] != v {
			t.Errorf("light --%s is %q in style.go, %q in brand.css", tok, v, wantLight[tok])
		}
	}
	for tok, v := range gotDark {
		if wantDark[tok] != v {
			t.Errorf("dark --%s is %q in style.go, %q in brand.css", tok, v, wantDark[tok])
		}
	}
	// Every token a page reads is one the palette defines, in both themes.
	for _, m := range regexp.MustCompile(`var\(--([\w-]+)\)`).FindAllStringSubmatch(pageBase+landingStyle+walletStyle, -1) {
		if _, ok := gotLight[m[1]]; !ok {
			t.Errorf("a server page reads --%s, which brandPalette does not define", m[1])
		}
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

// A pill in a table cell is one value — a status, a count, a kind — and it breaks between words or
// not at all. `overflow-wrap:anywhere` let a narrow status column split "active" into "activ" / "e"
// (owner, 2026-09-29, on the Overview's status column). The rule is held here because the pill is
// shared by every table in both portals: the cloud harvests this stylesheet.
func TestAPillInATableNeverBreaksInsideAWord(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	rule := regexp.MustCompile(`(?m)^td \.pill\{([^}]*)\}`).FindStringSubmatch(string(b))
	if rule == nil {
		t.Fatal("style.css has no `td .pill` rule, so a pill in a table inherits the cell's wrapping")
	}
	decl := strings.ReplaceAll(rule[1], " ", "")
	for _, bad := range []string{"overflow-wrap:anywhere", "word-break:break-all", "word-break:break-word", "overflow-wrap:break-word"} {
		if strings.Contains(decl, bad) {
			t.Errorf("td .pill declares %s, which breaks a one-word status inside the word: %s", bad, rule[1])
		}
	}
	if !strings.Contains(decl, "word-break:keep-all") && !strings.Contains(decl, "white-space:nowrap") {
		t.Errorf("td .pill neither keeps words whole nor refuses to wrap: %s", rule[1])
	}
}

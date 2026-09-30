package internalui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/web"
)

// The web wallet's return page (2026-09-30): the portal's look, one worded state for every answer
// the flow has, and the install's refusals told apart by a code the page words.

// walletInstallEnv mounts the wallet pages over a store holding alice, administered by owner-a,
// with `install` as the node's install.
func walletInstallEnv(t *testing.T, install func(*http.Request, store.Account, [][]byte, string) (WalletInstalled, error)) *http.ServeMux {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice Rao", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"owner-a", "owner-b"} {
		if _, err := e.st.CreateOwnerWithID(ctx, o, o); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.st.AddMembership(ctx, "owner-a", a.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	MountWalletPages(mux, WalletDeps{Store: e.st, Install: install, Audit: func(string, string, string) {}})
	return mux
}

// postInstall POSTs an answer as `owner` and returns the status and the JSON answer.
func postInstall(t *testing.T, mux *http.ServeMux, owner, slug string, form url.Values) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/identity/"+slug+"/wallet/install", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), ownerKey{}, owner))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("the install answered %d with no JSON: %s", rec.Code, rec.Body)
	}
	return rec.Code, out
}

var goodAnswer = url.Values{"chain": {"AQ.Ag"}, "state": {strings.Repeat("s", 43)}}

// Every refusal of the install carries its code; the identity package's sentinels each reach theirs
// however they are wrapped, and the plain ErrRequestState — a request is waiting, and this answer
// is not for it — is told apart from the answer installed already and from no request at all.
func TestEachInstallRefusalAnswersItsCode(t *testing.T) {
	var next error
	mux := walletInstallEnv(t, func(*http.Request, store.Account, [][]byte, string) (WalletInstalled, error) {
		return WalletInstalled{}, next
	})
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("x: %w: %w", identity.ErrRequestAnswered, identity.ErrRequestState), 409, "answered"},
		{fmt.Errorf("x: %w: %w", identity.ErrNoRequest, identity.ErrRequestState), 409, "no_request"},
		{fmt.Errorf("x: %w", identity.ErrRequestState), 409, "not_this_request"},
		{fmt.Errorf("x: %w: %w", identity.ErrWrongRoot, identity.ErrLeafRefused), 400, "wrong_root"},
		{fmt.Errorf("x: %w: %w", identity.ErrWrongKey, identity.ErrLeafRefused), 400, "wrong_key"},
		{fmt.Errorf("x: %w: %w", identity.ErrNotNewer, identity.ErrLeafRefused), 400, "not_newer"},
		{fmt.Errorf("identity: chain refused by rule 4: leaf outside its validity: %w", identity.ErrLeafRefused), 400, "chain"},
		{errors.New("sqlite: disk I/O error at /var/lib/pact/pact.db"), 500, "failed"},
	}
	for _, c := range cases {
		next = c.err
		status, out := postInstall(t, mux, "owner-a", "alice", goodAnswer)
		if status != c.status || out["code"] != c.code {
			t.Errorf("%v: answered %d %v, want %d %q", c.err, status, out, c.status, c.code)
		}
		msg, _ := out["error"].(string)
		switch c.code {
		case "chain":
			if msg != "chain refused by rule 4: leaf outside its validity" {
				t.Errorf("a refused chain does not say which rule: %q", msg)
			}
		case "failed":
			if strings.Contains(msg, "sqlite") || strings.Contains(msg, "/var/lib") {
				t.Errorf("a failure of this node carries its error's text: %q", msg)
			}
		}
	}
	// The ones decided before the install: an identity that is not the caller's, one that does not
	// exist, an answer that is not one.
	for _, c := range []struct {
		owner, slug string
		form        url.Values
		status      int
		code        string
	}{
		{"owner-b", "alice", goodAnswer, 404, "not_found"},
		{"owner-a", "nobody", goodAnswer, 404, "not_found"},
		{"owner-a", "alice", url.Values{"chain": {"AQ.Ag"}}, 400, "malformed"},
		{"owner-a", "alice", url.Values{"chain": {"not-a-chain"}, "state": {"s"}}, 400, "malformed"},
	} {
		if status, out := postInstall(t, mux, c.owner, c.slug, c.form); status != c.status || out["code"] != c.code {
			t.Errorf("%s on %s with %v: answered %d %v, want %d %q", c.owner, c.slug, c.form, status, out, c.status, c.code)
		}
	}
}

// An install that goes in answers what the page shows: the identity's name, its address, and the
// certificate's validity as the wallet's chain gives it.
func TestAnInstallAnswersWhatWasInstalled(t *testing.T) {
	nb := time.Date(2026, 9, 30, 14, 5, 9, 0, time.UTC)
	mux := walletInstallEnv(t, func(*http.Request, store.Account, [][]byte, string) (WalletInstalled, error) {
		return WalletInstalled{Endpoint: "https://node.example/a/alice/mcp", NotBefore: nb, NotAfter: nb.AddDate(1, 0, 0)}, nil
	})
	status, out := postInstall(t, mux, "owner-a", "alice", goodAnswer)
	if status != 200 || out["name"] != "Alice Rao" || out["endpoint"] != "https://node.example/a/alice/mcp" ||
		out["not_before"] != "2026-09-30T14:05:09Z" || out["not_after"] != "2027-09-30T14:05:09Z" {
		t.Fatalf("the install answered %d %v", status, out)
	}
	if _, ok := out["code"]; ok {
		t.Fatalf("an install that went in carries a refusal code: %v", out)
	}
}

// returnPage renders GET /wallet/return.
func returnPage(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	MountWalletPages(mux, WalletDeps{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/return?slug=alice", nil))
	if rec.Code != 200 {
		t.Fatalf("the return page answered %d", rec.Code)
	}
	return rec.Body.String()
}

// section is the markup of the page's state `id`.
func section(t *testing.T, page, id string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<section id="st-` + regexp.QuoteMeta(id) + `"[^>]*>(.*?)</section>`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the return page has no state %q", id)
	}
	return m[1]
}

// Every code the install answers is a state of the return page, and so is every other way the
// flow ends: each says in words what happened (a heading, and a pill where it is a result), so no
// state is told by its colour alone.
func TestEveryWalletRefusalIsWordedOnTheReturnPage(t *testing.T) {
	page := returnPage(t)
	codes := []string{"not_found", "malformed", "chain", "failed"}
	for _, rf := range walletRefusals {
		codes = append(codes, rf.code)
	}
	var states []string
	for _, c := range codes {
		states = append(states, "r-"+c)
	}
	states = append(states, "working", "installed", "signed_out", "forbidden", "unreachable", "refused",
		"wallet_cancelled", "wallet_failed", "wallet_other", "empty")
	heading := regexp.MustCompile(`<h2>([^<]{8,})</h2>`)
	for _, s := range states {
		body := section(t, page, s)
		if !heading.MatchString(body) {
			t.Errorf("state %q has no worded heading", s)
		}
		if s != "working" && !strings.Contains(page, `<section id="st-`+s+`" hidden>`) {
			t.Errorf("state %q is not hidden until the script shows it", s)
		}
		if s != "empty" && !strings.Contains(body, `class="pill`) {
			t.Errorf("state %q has no pill naming its result", s)
		}
	}
	// Each state's words are its own: two states that read the same are one state shown twice.
	seen := map[string]string{}
	for _, s := range states {
		h := heading.FindStringSubmatch(section(t, page, s))
		if h == nil {
			continue
		}
		if prev, ok := seen[h[1]]; ok {
			t.Errorf("states %q and %q share the heading %q", prev, s, h[1])
		}
		seen[h[1]] = s
	}
	// No raw code is a headline.
	for _, c := range codes {
		if regexp.MustCompile(`<h2>[^<]*\b` + c + `\b`).MatchString(page) {
			t.Errorf("the code %q is a heading", c)
		}
	}
}

// The page is accessible as it changes: the card is a polite live region present from the start
// (never hidden itself, so the change inside it is announced) and marked busy until the result;
// the marks are decoration; motion stops under reduced motion.
func TestTheWalletReturnPageAnnouncesItsResult(t *testing.T) {
	page := returnPage(t)
	if !regexp.MustCompile(`<div class="card wr-card" id="answer" data-kind="working" role="status" aria-live="polite" aria-busy="true">`).MatchString(page) {
		t.Error("the answer card is not a polite live region marked busy")
	}
	for _, m := range regexp.MustCompile(`<svg[^>]*>`).FindAllString(page, -1) {
		if !strings.Contains(m, `aria-hidden="true"`) {
			t.Errorf("a mark is not hidden from assistive technology: %s", m)
		}
	}
	if !regexp.MustCompile(`@media \(prefers-reduced-motion:reduce\)\{[^}]*\.wr-spin[^}]*animation:none`).MatchString(walletReturnStyle) {
		t.Error("the spinner turns under reduced motion")
	}
	if !strings.Contains(walletReturnStyle, "[hidden]{display:none!important}") {
		t.Error("the portal's .btn and .notice display would show a hidden action or state")
	}
}

// The page is the portal's: it links the SPA's own built stylesheet (which carries brand.css and
// style.css), and that file holds every rule the page's markup names. Its own few rules read only
// tokens brand.css defines, light and dark.
func TestTheWalletReturnPageIsThePortals(t *testing.T) {
	page := returnPage(t)
	if !strings.Contains(page, `<link rel="stylesheet" href="`+portalStylesheet+`"/>`) {
		t.Fatalf("the return page does not link the portal's stylesheet %s", portalStylesheet)
	}
	css, err := fs.ReadFile(web.Dist, "dist"+portalStylesheet)
	if err != nil {
		t.Fatalf("the linked stylesheet is not in the embedded build: %v", err)
	}
	for _, sel := range []string{".center{", ".center .brandline{", ".center .brandline .logo{", ".card{", ".btn.secondary{",
		".pill{", ".pill.ok{", ".pill.warn{", ".pill.bad{", "dl.facts{", ".notice.warn{", ".notice.err{", ".toolbar{", ".help{",
		"@keyframes spin", "@keyframes rise", "--red-soft:", "--amber-soft:", "prefers-color-scheme:dark"} {
		if !strings.Contains(string(css), sel) {
			t.Errorf("the portal's stylesheet has no %q, which the return page relies on", sel)
		}
	}
	b, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "brand.css"))
	if err != nil {
		t.Fatal(err)
	}
	brand := string(b)
	light := regexp.MustCompile(`/\* palette:light \*/\s*:root\s*\{([^}]*)\}`).FindStringSubmatch(brand)
	dark := regexp.MustCompile(`/\* palette:dark \*/\s*@media \(prefers-color-scheme: dark\)\s*\{\s*:root\s*\{([^}]*)\}`).FindStringSubmatch(brand)
	if light == nil || dark == nil {
		t.Fatal("brand.css has lost its palette:light or palette:dark block")
	}
	lightTok, darkTok := paletteOf(light[1]), paletteOf(dark[1])
	used := regexp.MustCompile(`var\(--([\w-]+)\)`).FindAllStringSubmatch(walletReturnStyle, -1)
	if len(used) < 5 {
		t.Fatalf("read %d tokens from the page's style; the scan is broken", len(used))
	}
	for _, m := range used {
		if _, ok := lightTok[m[1]]; !ok {
			t.Errorf("the return page reads --%s, which brand.css's light palette does not define", m[1])
		}
		// --ease-out and the type faces are theme-free: defined once, in the light block.
		if _, ok := darkTok[m[1]]; !ok && m[1] != "ease-out" && m[1] != "mono" {
			t.Errorf("the return page reads --%s, which brand.css does not redefine for dark", m[1])
		}
	}
	// The logo stands still: the column's entrance does not carry it.
	if !strings.Contains(walletReturnStyle, ".wr > .brandline{animation:none}") {
		t.Error("the SPA's entrance for main.center's children moves the logo on this page")
	}
	// Phone width: the portal's 24px gutter is 16px here.
	if !regexp.MustCompile(`@media \(max-width:600px\)\{main\.center\.wr\{[^}]*padding:0 16px`).MatchString(walletReturnStyle) {
		t.Error("no 16px gutter at phone width")
	}
}

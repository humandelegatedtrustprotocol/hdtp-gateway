package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// walletBrowser is a browser on the node's portal: a session cookie (or none) and the CSRF cookie.
type walletBrowser struct {
	t       *testing.T
	base    string
	session *http.Cookie
	csrf    *http.Cookie
}

func (p *walletBrowser) do(method, path string, form url.Values, header map[string]string) (*http.Response, string) {
	p.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, p.base+path, body)
	if err != nil {
		p.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for _, c := range []*http.Cookie{p.session, p.csrf} {
		if c != nil {
			req.AddCookie(c)
		}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, "pact_csrf") {
			p.csrf = c
		}
	}
	return res, string(b)
}

// formFields reads the one form on a page: its action and its inputs, in order. The pages are the
// node's own templates, so a pattern over their markup is enough.
func formFields(t *testing.T, page string) (string, [][2]string) {
	t.Helper()
	var action string
	if m := regexp.MustCompile(`<form[^>]*action="([^"]*)"`).FindStringSubmatch(page); m != nil {
		action = html.UnescapeString(m[1])
	}
	var fields [][2]string
	for _, m := range regexp.MustCompile(`<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"`).FindAllStringSubmatch(page, -1) {
		fields = append(fields, [2]string{html.UnescapeString(m[1]), html.UnescapeString(m[2])})
	}
	if n := strings.Count(page, "<input"); n != len(fields) {
		t.Fatalf("the page has %d inputs and %d were read", n, len(fields))
	}
	return action, fields
}

// The web wallet's signing request, end to end on a running node, with a test playing the wallet
// (PACT §9.1): the page that asks changes nothing; starting mints a request whose form is exactly
// what a wallet accepts; the answer is refused without a session, with another state, over another
// key, under another root, and a second time; the one answer that must pass is installed and the
// LIVE node serves the new chain.
func TestTheWebWalletSigningRequestOnARunningNode(t *testing.T) {
	ctx := context.Background()
	var alice store.Account
	var ownerID string
	key, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rootDER, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Alice", Key: key, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(csr []byte, prev *time.Time, k *pactidentity.PrivateKey, root []byte) string {
		iss, err := pactidentity.IssueFromCSR(csr, pactidentity.IssueOpts{RootCN: "Alice", RootKey: k, RootSPKIs: [][]byte{k.Public().SPKI},
			Now: time.Now(), PreviousNotBefore: prev, ValidDays: 365})
		if err != nil {
			t.Fatal(err)
		}
		return pactidentity.B64url(iss.DER) + "." + pactidentity.B64url(root)
	}
	// A public address the wallet's address guard accepts (a loopback one it refuses to certify).
	r := runServeWith(t, map[string]any{"public_url": "https://alice.pact.example"}, func(t *testing.T, dir string) {
		st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		o, err := st.CreateOwnerWithID(ctx, "", "Owner")
		if err != nil {
			t.Fatal(err)
		}
		ownerID = o.ID
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		a, err := idm.CreateAccount(ctx, "alice", "Alice", identity.AlgoP256)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().Add(-time.Hour)
		csr, err := idm.IssueCSR(ctx, a.ID, identity.PurposeSignup, identity.EndpointFor(configPublicURL(t, dir), "alice"), now)
		if err != nil {
			t.Fatal(err)
		}
		iss, err := pactidentity.IssueFromCSR(csr.CSR, pactidentity.IssueOpts{RootCN: "Alice", RootKey: key, RootSPKIs: [][]byte{key.Public().SPKI}, Now: now, ValidDays: 365})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := idm.InstallLeaf(ctx, a.ID, [][]byte{iss.DER, rootDER}, now); err != nil {
			t.Fatal(err)
		}
		if alice, err = st.GetAccountByID(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
	})
	st := openStoreAt(t, r.dir)
	cfg, err := loadConfig(filepath.Join(r.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.New(st).MintSession(ctx, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + r.internal
	signedIn := &walletBrowser{t: t, base: base, session: &http.Cookie{Name: "pact_session_" + cfg.Tag(), Value: token}}
	pending := func() []store.Leaf {
		leaves, err := st.ListLeaves(ctx, alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		var out []store.Leaf
		for _, l := range leaves {
			if l.State == identity.LeafPending {
				out = append(out, l)
			}
		}
		return out
	}

	// 1. The page that asks writes nothing, and is not stored by the browser.
	res, page := signedIn.do("GET", "/identity/alice/wallet", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(page, "Continue to my wallet") || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("the asking page: %d %q %s", res.StatusCode, res.Header.Get("Cache-Control"), page)
	}
	if got := pending(); len(got) != 0 {
		t.Fatalf("GET minted a request: %+v", got)
	}
	// Without a session: to sign in, and back to the page after, whether or not the slug exists.
	if res, _ := (&walletBrowser{t: t, base: base}).do("GET", "/identity/alice/wallet", nil, nil); res.StatusCode != 303 || res.Header.Get("Location") != "/login?next=%2Fidentity%2Falice%2Fwallet" {
		t.Fatalf("the asking page without a session: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := signedIn.do("GET", "/identity/nobody/wallet", nil, nil); res.StatusCode != 404 {
		t.Fatalf("a slug this node does not hold: %d", res.StatusCode)
	}
	// An owner of this node who does not administer alice gets the answer a slug that does not
	// exist gets, on every door.
	other, err := st.CreateOwnerWithID(ctx, "", "Other")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, err := auth.New(st).MintSession(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	outsider := &walletBrowser{t: t, base: base, session: &http.Cookie{Name: "pact_session_" + cfg.Tag(), Value: otherToken}}
	if res, _ := outsider.do("GET", "/identity/alice/wallet", nil, nil); res.StatusCode != 404 {
		t.Fatalf("another owner's view of alice's request: %d", res.StatusCode)
	}
	if res, _ := outsider.do("POST", "/identity/alice/wallet/start", url.Values{"csrf": {outsider.csrf.Value}}, nil); res.StatusCode != 404 {
		t.Fatalf("another owner starting alice's request: %d", res.StatusCode)
	}
	if res, _ := outsider.do("POST", "/identity/alice/wallet/install", url.Values{"chain": {"a.b"}, "state": {"s"}}, map[string]string{"X-Pact-Csrf": outsider.csrf.Value}); res.StatusCode != 404 {
		t.Fatalf("another owner installing into alice: %d", res.StatusCode)
	}
	if got := pending(); len(got) != 0 {
		t.Fatalf("another owner minted a request: %+v", got)
	}

	// A browser that has never been to the portal (a bookmark, a link) has no CSRF cookie: the page
	// it is given must still carry a token its own form can submit.
	fresh := &walletBrowser{t: t, base: base, session: signedIn.session}
	res, page = fresh.do("GET", "/identity/alice/wallet", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("the asking page to a fresh browser: %d", res.StatusCode)
	}
	if action, fields := formFields(t, page); action != "/identity/alice/wallet/start" {
		t.Fatalf("the asking page's form goes to %q", action)
	} else {
		f := url.Values{}
		for _, kv := range fields {
			f.Set(kv[0], kv[1])
		}
		if f.Get("csrf") == "" || f.Get("csrf") != fresh.csrf.Value {
			t.Fatalf("the page's token %q is not the cookie it set %q", f.Get("csrf"), fresh.csrf.Value)
		}
	}

	// 2. Start: the form is exactly the signing request a wallet takes.
	start := func(replace bool) (*http.Response, string) {
		f := url.Values{"csrf": {signedIn.csrf.Value}}
		if replace {
			f.Set("replace", "1")
		}
		return signedIn.do("POST", "/identity/alice/wallet/start", f, nil)
	}
	res, page = start(false)
	if res.StatusCode != 200 {
		t.Fatalf("start: %d %s", res.StatusCode, page)
	}
	if got := res.Header.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("the form page's Referrer-Policy is %q: under no-referrer the wallet sees Origin: null", got)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://ceremony.pact.contact;") || !strings.Contains(csp, "script-src 'self';") {
		t.Errorf("the form page's CSP: %q", csp)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("the form page may be stored: %q", res.Header.Get("Cache-Control"))
	}
	action, fields := formFields(t, page)
	if action != "https://ceremony.pact.contact/sign" {
		t.Fatalf("the form goes to %q", action)
	}
	got := map[string]string{}
	var names []string
	for _, f := range fields {
		got[f[0]] = f[1]
		names = append(names, f[0])
	}
	// The wallet's own check, from the released pact-identity: the node's form and the wallet's list
	// of members are two copies of one list, and this holds them together. The origin is the one the
	// browser sends with the form: the portal's.
	request := map[string]any{}
	for _, f := range fields {
		request[f[0]] = f[1]
	}
	if _, err := pactidentity.SigningRequestCheck(request, base, time.Now(), [][]byte{key.Public().SPKI}); err != nil {
		t.Fatalf("the wallet refuses the request this node sends: %v", err)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "csr,expect_root,expires,purpose,recipient,redirect,root_cert,state,valid_days" {
		t.Fatalf("the form carries %v; a wallet refuses a request with any other member (a csrf field included)", names)
	}
	b64 := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(got["state"]) {
		t.Errorf("state %q", got["state"])
	}
	if got["purpose"] != "renew" || got["valid_days"] != "365" || got["expect_root"] != alice.RootFingerprint ||
		!regexp.MustCompile(`^sha256:[A-Za-z0-9_-]{43}$`).MatchString(got["expect_root"]) {
		t.Errorf("purpose %q valid_days %q expect_root %q (root %q)", got["purpose"], got["valid_days"], got["expect_root"], alice.RootFingerprint)
	}
	if !b64.MatchString(got["csr"]) || len(got["csr"]) > 4096 || !b64.MatchString(got["root_cert"]) || got["root_cert"] != pactidentity.B64url(rootDER) {
		t.Errorf("csr or root_cert is not base64url DER: %q %q", got["csr"], got["root_cert"])
	}
	if got["redirect"] != base+"/wallet/return?slug=alice" || len([]rune(got["recipient"])) > 200 || got["recipient"] == "" {
		t.Errorf("redirect %q recipient %q", got["redirect"], got["recipient"])
	}
	exp, err := time.Parse(time.RFC3339, got["expires"])
	if err != nil || !strings.HasSuffix(got["expires"], "Z") || !exp.After(time.Now()) || exp.After(time.Now().Add(600*time.Second)) {
		t.Errorf("expires %q is not UTC, after now and at most 600 s ahead", got["expires"])
	}
	csrDER := testid.DER(t, got["csr"])
	firstState := got["state"]
	if p := pending(); len(p) != 1 || p[0].WalletOrigin != "https://ceremony.pact.contact" {
		t.Fatalf("pending after start: %+v", p)
	}

	// 3. A request is waiting: starting again is refused unless it says it replaces it.
	if res, _ := start(false); res.StatusCode != 409 {
		t.Fatalf("a second start over a pending request: %d", res.StatusCode)
	}
	res, page = start(true)
	if res.StatusCode != 200 {
		t.Fatalf("replace: %d", res.StatusCode)
	}
	_, fields = formFields(t, page)
	for _, f := range fields {
		got[f[0]] = f[1]
	}
	state := got["state"]
	csrDER2 := testid.DER(t, got["csr"])
	if state == firstState {
		t.Fatal("the replacement carries the replaced request's state")
	}

	// 4. The wallet's answers.
	var current store.Leaf
	leaves, _ := st.ListLeaves(ctx, alice.ID)
	for _, l := range leaves {
		if l.State == identity.LeafCurrent {
			current = l
		}
	}
	prev := time.Unix(current.NotBefore, 0)
	good := issue(csrDER2, &prev, key, rootDER)
	install := func(p *walletBrowser, chain, state string) (*http.Response, string) {
		return p.do("POST", "/identity/alice/wallet/install", url.Values{"chain": {chain}, "state": {state}},
			map[string]string{"X-Pact-Csrf": signedIn.csrf.Value})
	}
	// No session: refused, and the request is still answerable afterwards.
	stranger := &walletBrowser{t: t, base: base, csrf: signedIn.csrf}
	if res, _ := install(stranger, good, state); res.StatusCode != 401 {
		t.Fatalf("install with no session: %d", res.StatusCode)
	}
	if p := pending(); len(p) != 1 || len(p[0].RequestStateHash) == 0 {
		t.Fatalf("a refused install used the request up: %+v", p)
	}
	// Each refusal carries the code the return page words it by (internalui.walletRefusals).
	code := func(body string) string {
		var j map[string]any
		if err := json.Unmarshal([]byte(body), &j); err != nil {
			t.Fatalf("a refusal that is not JSON: %s", body)
		}
		c, _ := j["code"].(string)
		return c
	}
	if res, body := install(signedIn, good, firstState); res.StatusCode != 409 || code(body) != "not_this_request" {
		t.Fatalf("the replaced request's state: %d %s", res.StatusCode, body)
	}
	if res, body := install(signedIn, good, strings.Repeat("A", 43)); res.StatusCode != 409 || code(body) != "not_this_request" {
		t.Fatalf("another state: %d %s", res.StatusCode, body)
	}
	if res, body := install(signedIn, issue(csrDER, &prev, key, rootDER), state); res.StatusCode != 400 || code(body) != "wrong_key" {
		t.Fatalf("a leaf over the replaced request's key: %d %s", res.StatusCode, body)
	}
	mallory, _ := pactidentity.GenerateKey("ed25519")
	malloryRoot, _ := pactidentity.BuildRoot(pactidentity.RootOpts{CN: "Alice", Key: mallory, NotBefore: time.Now().Add(-time.Hour)})
	if res, body := install(signedIn, issue(csrDER2, &prev, mallory, malloryRoot), state); res.StatusCode != 400 || code(body) != "wrong_root" {
		t.Fatalf("a leaf under another root: %d %s", res.StatusCode, body)
	}
	if res, body := install(signedIn, "not-a-chain", state); res.StatusCode != 400 || code(body) != "malformed" {
		t.Fatalf("a malformed chain: %d %s", res.StatusCode, body)
	}
	// A character outside base64url is refused as the identity core refuses it (pact-identity
	// 0.4.2's DecodeB64url), before the request is looked up. The reader this replaced skipped
	// the character, so this call installed the chain and spent the request the pass below needs.
	if res, body := install(signedIn, "!"+good, state); res.StatusCode != 400 || code(body) != "malformed" {
		t.Fatalf("a chain with a character outside base64url: %d %s", res.StatusCode, body)
	}
	// The one that must pass.
	res, body := install(signedIn, good, state)
	if res.StatusCode != 200 {
		t.Fatalf("the answer that must pass: %d %s", res.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil || out["endpoint"] != identity.EndpointFor(cfg.PublicURL, "alice") || out["notice"] != "" || out["name"] != "Alice" {
		t.Fatalf("install answered %s", body)
	}
	// The validity is the installed leaf's, as the chain gives it.
	leafCert, err := pactidentity.Parse(testid.DER(t, strings.Split(good, ".")[0]))
	if err != nil {
		t.Fatal(err)
	}
	if out["not_before"] != leafCert.NotBefore.UTC().Format(time.RFC3339) || out["not_after"] != leafCert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("install answered validity %v to %v; the leaf says %v to %v", out["not_before"], out["not_after"], leafCert.NotBefore, leafCert.NotAfter)
	}
	if res, body := install(signedIn, good, state); res.StatusCode != 409 || code(body) != "answered" {
		t.Fatalf("the same answer twice: %d %s", res.StatusCode, body)
	}
	// With nothing pending now, a state never minted is not an answer installed before.
	if res, body := install(signedIn, good, strings.Repeat("C", 43)); res.StatusCode != 409 || code(body) != "no_request" {
		t.Fatalf("a state never minted, nothing pending: %d %s", res.StatusCode, body)
	}
	// The running node presents the leaf just installed: the install went through the service
	// that reloads it, not only into the store.
	leafDER := testid.DER(t, strings.Split(good, ".")[0])
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "alice.pact.example"}}}
	hres, err := c.Get("https://" + r.public + "/a/alice/mcp")
	if err != nil {
		t.Fatal(err)
	}
	hres.Body.Close()
	if !bytes.Equal(hres.TLS.PeerCertificates[0].Raw, leafDER) {
		t.Fatal("the live node still presents the old leaf")
	}

	// 5. One audit row per act, naming the account, with the outcome as it happened.
	events, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, e := range events {
		switch e.Action {
		case "account_csr", "account_leaf_install", "account_leaf_install_refused":
			if e.AccountID != alice.ID {
				t.Errorf("%s names account %q", e.Action, e.AccountID)
			}
			if e.Action == "account_csr" && e.Outcome == "ok" && !strings.Contains(e.Resource, "wallet_origin:https://ceremony.pact.contact") {
				continue // the seed's own requests, made before the node started, are not audited here
			}
			seen = append(seen, e.Action+"/"+e.Outcome)
		}
	}
	want := "account_csr/ok,account_csr/refused,account_csr/ok,account_leaf_install_refused/refused,account_leaf_install_refused/refused," +
		"account_leaf_install_refused/refused,account_leaf_install_refused/refused,account_leaf_install_refused/refused,account_leaf_install_refused/refused,account_leaf_install/ok,account_leaf_install_refused/refused," +
		"account_leaf_install_refused/refused"
	if strings.Join(seen, ",") != want {
		t.Fatalf("audit rows\n got %s\nwant %s", strings.Join(seen, ","), want)
	}
}

// The page a web wallet navigates back to is served with no session (the wallet's navigation is
// cross-site, so the Strict cookies are not sent), holds no data, keeps the portal's policy, and
// names the CSRF cookie its script reads. Its script is served the same way.
func TestTheWalletReturnPageNeedsNoSessionAndHoldsNoData(t *testing.T) {
	r := runServe(t, nil)
	cfg, err := loadConfig(filepath.Join(r.dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &walletBrowser{t: t, base: "http://" + r.internal}
	res, page := p.do("GET", "/wallet/return?slug=alice", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(page, `<script src="/wallet/return.js"></script>`) ||
		!strings.Contains(page, `content="pact_csrf_`+cfg.Tag()+`"`) {
		t.Fatalf("return page: %d %s", res.StatusCode, page)
	}
	if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "form-action 'self';") ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "script-src 'self';") {
		t.Fatalf("return page headers: %v", res.Header)
	}
	// No inline script of any kind: every <script> names its file, and no element carries a handler
	// attribute or a javascript: URL. The portal's CSP (script-src 'self') would refuse each.
	for _, tag := range regexp.MustCompile(`(?i)<script\b[^>]*>`).FindAllString(page, -1) {
		if !regexp.MustCompile(`\ssrc="/[^"]+"`).MatchString(tag) {
			t.Fatalf("an inline script, which the portal's CSP refuses: %s", tag)
		}
	}
	if m := regexp.MustCompile(`(?i)<[^>]*\son[a-z]+\s*=|javascript:`).FindString(page); m != "" {
		t.Fatalf("inline script in markup: %s", m)
	}
	// The portal's stylesheet it links is served without a session, like the sign-in page's.
	css := regexp.MustCompile(`<link rel="stylesheet" href="(/assets/[^"]+\.css)"/>`).FindStringSubmatch(page)
	if css == nil {
		t.Fatal("the return page links no portal stylesheet")
	}
	if res, body := p.do("GET", css[1], nil, nil); res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/css") || !strings.Contains(body, ".brandline") {
		t.Fatalf("the portal's stylesheet without a session: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	res, js := p.do("GET", "/wallet/return.js", nil, nil)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/javascript") || !strings.Contains(js, "history.replaceState") {
		t.Fatalf("return.js: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	// Open, not merely falling through: a GET without a session is served either way, but one
	// outside the open set is audited as a request that lacked an identity, and a wallet's return
	// is not that.
	events, err := openStoreAt(t, r.dir).ListAuditEvents(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == "portal_request" && strings.Contains(e.Resource, "/wallet/return") {
			t.Fatalf("the return page was refused an identity: %s %s", e.Resource, e.Outcome)
		}
	}
	// The install it POSTs to is NOT open.
	if res, _ := p.do("POST", "/identity/alice/wallet/install", url.Values{"chain": {"a.b"}, "state": {"s"}}, nil); res.StatusCode != 401 {
		t.Fatalf("install with no session: %d", res.StatusCode)
	}
}

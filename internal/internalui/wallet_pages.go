package internalui

// The signing request to a web wallet (HDTP §9.1; the identity-boundary design §2): the portal asks
// the person's web wallet for a leaf, and installs the answer.
//
//	GET  /identity/{slug}/wallet          what would be asked, and of which wallet. Changes nothing.
//	POST /identity/{slug}/wallet/start    mints the request (leafService.Mint, audited account_csr)
//	                                      and answers with a page whose form POSTs it to the wallet
//	GET  /wallet/return                   where the wallet navigates back to, the answer in the
//	                                      fragment; served without a session and holding no data
//	POST /identity/{slug}/wallet/install  the answer, POSTed same-site by /wallet/return's script
//	                                      with the session and the CSRF header (leafService.Install)
//
// The pages are server-rendered, on the model of the invite landing page: the SPA's CSP admits no
// inline script, so each page's script is a file of its own (/wallet/submit.js, /wallet/return.js).
// Why the answer comes back in a fragment and is POSTed from the page rather than sent as a
// cross-site POST: the session and CSRF cookies are SameSite=Strict, so a cross-site POST would
// arrive with neither, and the install would need a route with no authorisation.

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// WalletInstalled is what an install did, as the return page reports it.
type WalletInstalled struct {
	Endpoint string
	// NotBefore and NotAfter are the installed leaf's validity, as the wallet's chain gives it.
	NotBefore, NotAfter time.Time
	// Notice is the move notice (identity.MoveNotice), "" when the identity did not move.
	Notice string
	// Warnings are what the install did not finish although the leaf is installed.
	Warnings []string
}

// WalletDeps is what the web-wallet pages call. Mint and Install are the node's one signing-request
// service (cli/leafservice.go), the same the admin socket calls.
type WalletDeps struct {
	Store store.Store
	// WalletOrigin is the web wallet's origin (config wallet_url); the request goes to its /sign.
	WalletOrigin string
	// Endpoint is the address a leaf for this slug names on this node; "" with no public URL.
	Endpoint func(slug string) string
	// Purpose is identity.Manager.WalletPurpose: renew or move, or a refusal for an account with no root.
	Purpose func(r *http.Request, accountID, endpoint string) (string, error)
	Mint    func(r *http.Request, acct store.Account, purpose, endpoint, walletOrigin string) (identity.CSRResult, error)
	Install func(r *http.Request, acct store.Account, chain [][]byte, state string) (WalletInstalled, error)
	Audit   func(action, resource, outcome string)
	Now     func() time.Time
}

func (d WalletDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d WalletDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// How far ahead a request expires. The wallet refuses one more than ten minutes ahead; eight leaves
// a margin for a wallet clock that runs ahead and still gives the person time on the page.
const walletRequestLifetime = 8 * time.Minute

// The validity a request suggests; the person chooses in the wallet (HDTP §9.1).
const walletSuggestedDays = 365

//go:embed wallet_submit.js
var walletSubmitJS []byte

//go:embed wallet_return.js
var walletReturnJS []byte

// walletStyle is portalStyle (style.go: the brand's palette, type and motion) and the wallet pages' own
// few rules: the facts as a two-column list, and a line's state by the brand's text colours.
const walletStyle = portalStyle + `<style>
 dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px}
 dt{color:var(--muted)}
 dd{margin:0;word-break:break-all}
 .err{color:var(--red)} .ok{color:var(--accent-ink)} .warn{color:var(--amber)}
</style>`

var walletAskTmpl = template.Must(template.New("ask").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sign with my web wallet</title>` + walletStyle + `</head>
<body><main>
` + portalBrand + `
<h1>Sign with my web wallet</h1>
<p>This node asks your wallet for a certificate for <strong>{{.Name}}</strong>. The wallet shows what it
names and asks for your passkey before it signs; nothing is signed from here.</p>
<dl><dt>Address</dt><dd>{{.Endpoint}}</dd><dt>Kind</dt><dd>{{.Purpose}}</dd><dt>Wallet</dt><dd>{{.Wallet}}</dd></dl>
{{if .Pending}}<p class="err">A request made {{.Pending}} is waiting for a wallet{{if .PendingWallet}} ({{.PendingWallet}}){{else}} (handed over by the command line){{end}}.
Continuing replaces it: a wallet's answer to that one will then be refused.</p>{{end}}
<form method="post" action="/identity/{{.Slug}}/wallet/start">
<input type="hidden" name="csrf" value="{{.CSRF}}"/>
{{if .Pending}}<input type="hidden" name="replace" value="1"/>{{end}}
<button type="submit">{{if .Pending}}Replace and continue{{else}}Continue to my wallet{{end}}</button>
</form>
<p class="muted">The wallet sends its answer back to this node's /wallet/return, in this browser.</p>
</main></body></html>`))

var walletSubmitTmpl = template.Must(template.New("submit").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Opening your wallet</title>` + walletStyle + `</head>
<body><main>
` + portalBrand + `
<h1>Opening your wallet…</h1>
<form id="wallet-form" method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}"/>
{{end}}<p class="muted">Your wallet is at {{.Wallet}}.</p>
<button type="submit">Continue to my wallet</button>
</form>
<script src="/wallet/submit.js"></script>
</main></body></html>`))

// The return page is laid out by the portal's own stylesheet (the SPA's built CSS, portalStylesheet):
// its sign-in column (.center, .brandline), .card, .btn, .pill, .notice and dl.facts, on brand.css's
// tokens, light and dark. walletReturnStyle is the page's own few rules on the same tokens;
// TestTheWalletReturnPageIsThePortals holds both to the SPA.
const walletReturnStyle = `<style>
[hidden]{display:none!important}
main.center.wr{max-width:32rem;margin-top:8vh;padding-bottom:3rem}
.wr > .brandline{animation:none}
.wr-card{padding:1.25rem 1.35rem}
.wr-card[data-kind="ok"]{border-color:color-mix(in srgb,var(--accent) 35%,var(--line))}
.wr-card[data-kind="warn"]{border-color:color-mix(in srgb,var(--amber) 40%,var(--line))}
.wr-card[data-kind="err"]{border-color:color-mix(in srgb,var(--red) 35%,var(--line))}
.wr-head{display:flex;gap:.85rem;align-items:flex-start}
.wr-head h2{margin:.35rem 0 .1rem;font-size:1.1rem}
.wr-icon{flex:0 0 auto;width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:var(--bg-3);color:var(--muted)}
.wr-icon svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.wr-card[data-kind="ok"] .wr-icon{background:var(--accent-soft);color:var(--accent-ink)}
.wr-card[data-kind="warn"] .wr-icon{background:var(--amber-soft);color:var(--amber)}
.wr-card[data-kind="err"] .wr-icon{background:var(--red-soft);color:var(--red)}
.wr-spin{width:18px;height:18px;border-radius:50%;border:2px solid currentColor;border-right-color:transparent;animation:spin .8s linear infinite}
.wr-card section > p,.wr-card section > dl,.wr-card section > .notice{margin:.9rem 0 0}
.wr-card section:not(#st-working){animation:rise .3s var(--ease-out) both}
.wr-card dl.facts dd{overflow-wrap:anywhere}
.wr-card dl.facts dd.mono{font-family:var(--mono);font-size:.84rem}
.wr-detail{margin:1rem 0 0;color:var(--faint);overflow-wrap:anywhere}
.wr-actions{margin-top:1.1rem;padding-top:1rem;border-top:1px solid var(--line)}
@media (max-width:600px){main.center.wr{margin-top:4vh;padding:0 16px 2rem}.wr-card{padding:1.05rem 1rem}.wr-actions .btn{flex:1 1 auto}}
@media (prefers-reduced-motion:reduce){.wr-spin,.wr-card section{animation:none!important}}
</style>`

// The return page's marks, in the portal's line style (1.8 stroke, round caps). Each state says in
// words what it is (its pill and its heading); the mark and the card's colour only repeat it.
const (
	wrIconOK   = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16.2 9.5"/></svg>`
	wrIconWarn = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.8L21.2 19.5H2.8z"/><path d="M12 10v4.2M12 16.9v.1"/></svg>`
	wrIconErr  = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"/></svg>`
	wrIconNone = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M8.5 12h7"/></svg>`
)

// wrState is one state of the return page: its section, its pill, its heading and what it says.
func wrState(id, icon, pill, pillClass, title, body string) string {
	p := ""
	if pill != "" {
		p = `<span class="pill ` + pillClass + `">` + pill + `</span>`
	}
	return `<section id="st-` + id + `" hidden><div class="wr-head"><span class="wr-icon">` + icon + `</span><div>` + p +
		`<h2>` + title + `</h2></div></div><p>` + body + `</p></section>
`
}

// The states the return page shows: one for each refusal the install answers, as r-<code>
// (walletRefusals, and not_found, malformed, chain, failed; the prefix keeps a code from naming any
// other state), for the portal's own refusals before it (signed_out, the 401; forbidden, the CSRF
// check's 403), for no reply at all, and for the wallet's own answers (#error=<code>: HDTP §9.1 names
// `cancelled`; BatonDeck's wallet also sends `failed`).
var walletReturnStates = wrState("r-answered", wrIconOK, "Already installed", "ok", "This answer was installed already",
	"Your wallet&#39;s answer was installed the first time it arrived here. Arriving again changes nothing. The Identity page shows the certificate this identity has now.") +
	wrState("r-not_this_request", wrIconErr, "Not installed", "bad", "This answer is for another request",
		"The request waiting here is not the one your wallet answered. A request is replaced when a new one is started, and the answer to the old one can no longer be used. Sign again to make a new request.") +
	wrState("r-no_request", wrIconErr, "Not installed", "bad", "No request is waiting",
		"This identity has no signing request waiting, so there is nothing for this answer to complete. Sign again to make a new request.") +
	wrState("r-wrong_root", wrIconErr, "Not installed", "bad", "Signed by a different wallet",
		"The certificate was signed by a root other than this identity&#39;s, so the wallet that answered does not hold this identity. Sign again, with the wallet that does.") +
	wrState("r-wrong_key", wrIconErr, "Not installed", "bad", "The certificate is for another key",
		"Your wallet certified a key other than the one this node asked it to. Sign again to make a new request.") +
	wrState("r-not_newer", wrIconErr, "Not installed", "bad", "Not newer than the current certificate",
		"The certificate your wallet signed does not start after the one this identity already has, and a new one must. Sign again to make a new request.") +
	wrState("r-chain", wrIconErr, "Not installed", "bad", "The certificate did not pass this node&#39;s checks",
		"This node checked the certificate against this identity and refused it; the line below names the rule. Sign again to make a new request.") +
	wrState("r-malformed", wrIconErr, "Not installed", "bad", "The answer was incomplete",
		"What came back from your wallet was not a whole answer, so there was nothing to install. Sign again to make a new request.") +
	wrState("r-not_found", wrIconErr, "Not installed", "bad", "Not an identity you manage here",
		"The identity this answer names is not one you manage on this node, or it no longer exists. Nothing was installed.") +
	wrState("r-failed", wrIconErr, "Not installed", "bad", "This node could not install the certificate",
		"Something failed on this node while installing it, and nothing was installed. The audit log records the attempt. Sign again to try once more.") +
	wrState("signed_out", wrIconErr, "Not installed", "bad", "Sign in to finish",
		"This browser is not signed in to this node&#39;s portal, so the answer could not be installed. Your wallet does not keep its answer: sign in, then sign again.") +
	wrState("forbidden", wrIconErr, "Not installed", "bad", "The install was refused",
		"This node could not confirm that the answer came from its own portal page in this browser, and refused it. Sign again from this browser.") +
	wrState("unreachable", wrIconWarn, "No reply", "warn", "This node did not reply",
		"The answer could not be delivered, or the reply to it was lost, so this page cannot say whether it was installed. The Identity page shows the certificate this identity has now.") +
	wrState("refused", wrIconErr, "Not installed", "bad", "This node refused the answer",
		"Nothing was installed. The line below is what this node said.") +
	wrState("wallet_cancelled", wrIconNone, "Not signed", "", "You declined in your wallet",
		"Nothing was signed and nothing was installed. Sign again when you are ready.") +
	wrState("wallet_failed", wrIconErr, "Not signed", "bad", "Your wallet could not sign",
		"Your wallet stopped before it signed, so nothing was installed. Sign again to try once more.") +
	wrState("wallet_other", wrIconErr, "Not signed", "bad", "Your wallet did not sign",
		"Nothing was installed.") +
	wrState("empty", wrIconNone, "", "", "Nothing to install",
		"This is where your wallet sends its answer, and none came with this visit. To sign, start from the Identity page.")

var walletReturnTmpl = template.Must(template.New("return").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="color-scheme" content="light dark"/>
<meta name="hdtp-csrf-cookie" content="{{.Cookie}}"/>
<title>Your wallet's answer</title>
<link rel="icon" href="/brand/favicon.svg" type="image/svg+xml"/>
<link rel="stylesheet" href="{{.Stylesheet}}"/>
` + walletReturnStyle + `</head>
<body><main class="center wr">
<div class="brandline"><picture><source srcset="/brand/hdtp-gateway-inline-dark.svg" media="(prefers-color-scheme: dark)"/><img class="logo" src="/brand/hdtp-gateway-inline.svg" alt="HDTP Gateway" width="183" height="34"/></picture></div>
<h1>Your wallet's answer</h1>
<div class="card wr-card" id="answer" data-kind="working" role="status" aria-live="polite" aria-busy="true">
<section id="st-working"><div class="wr-head"><span class="wr-icon"><span class="wr-spin" aria-hidden="true"></span></span><div><span class="pill">Working</span><h2>Installing your certificate…</h2></div></div>
<p>This node is checking your wallet's answer.</p>
<noscript><div class="notice err"><div class="body">Installing the certificate needs this page's script, and it did not run.</div></div></noscript></section>
<section id="st-installed" hidden><div class="wr-head"><span class="wr-icon"><span id="i-installed">` + wrIconOK + `</span><span id="i-installed-warn" hidden>` + wrIconWarn + `</span></span><div><span class="pill ok" id="p-installed">Installed</span><span class="pill warn" id="p-installed-warn" hidden>Installed, one thing left</span><h2>Your certificate is installed</h2></div></div>
<dl class="facts"><dt>Identity</dt><dd id="f-name"></dd><dt>Address</dt><dd class="mono" id="f-address"></dd><dt>Valid from</dt><dd id="f-from"></dd><dt>Valid until</dt><dd id="f-until"></dd></dl>
<p id="f-notice" hidden></p>
<div class="notice warn" id="f-warn" hidden><div class="body"><strong class="title">One thing is left to do</strong><span id="f-warnings"></span></div></div></section>
` + walletReturnStates + `<p class="help mono wr-detail" id="detail" hidden></p>
<div class="toolbar wr-actions" id="actions" hidden><a class="btn" id="a-login" hidden>Sign in</a><a class="btn" id="a-sign" hidden>Sign again</a><a class="btn secondary" id="a-back" href="/identity">Back to Identity</a></div>
</div>
<script src="/wallet/return.js"></script>
</main></body></html>`))

type walletField struct{ Name, Value string }

// MountWalletPages registers the web-wallet routes. /wallet/return and its script are in the
// session middleware's open set (auth_pages.go); everything else needs a signed-in owner who
// administers the account, and every POST passes the CSRF check.
func MountWalletPages(mux *http.ServeMux, d WalletDeps) {
	mux.HandleFunc("GET /identity/{slug}/wallet", d.getWallet)
	mux.HandleFunc("POST /identity/{slug}/wallet/start", d.postWalletStart)
	mux.HandleFunc("POST /identity/{slug}/wallet/install", d.postWalletInstall)
	mux.HandleFunc("GET /wallet/return", d.getWalletReturn)
	mux.HandleFunc("GET /wallet/submit.js", staticScript(walletSubmitJS))
	mux.HandleFunc("GET /wallet/return.js", staticScript(walletReturnJS))
}

func staticScript(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	}
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// walletAccount resolves the slug to an account the signed-in owner administers; 404 otherwise,
// for a slug that does not exist and one that belongs to someone else alike.
func (d WalletDeps) walletAccount(w http.ResponseWriter, r *http.Request) (store.Account, bool) {
	a, err := d.Store.GetAccountBySlug(r.Context(), r.PathValue("slug"))
	if err != nil || !ownerAdmins(r, d.Store, a.ID) {
		http.NotFound(w, r)
		return store.Account{}, false
	}
	return a, true
}

// walletPortalOrigin is this portal's origin as the browser sees it, which is what the browser will send
// as the request's Origin and so what the redirect must name. A wallet answers only https, or http
// to a loopback host; anything else is refused here rather than minted for a wallet to refuse.
func walletPortalOrigin(r *http.Request) (string, error) {
	o := browserOrigin(r)
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return "", errors.New("this portal's address could not be read from the request")
	}
	if u.Scheme == "https" {
		return o, nil
	}
	host := u.Host
	if u.Port() != "" {
		host = strings.TrimSuffix(host, ":"+u.Port())
	}
	if walletLoopbackHost(host) {
		return o, nil
	}
	return "", errors.New("this portal is served over http at an address that is not this machine; a web wallet sends its answer only to https, or to http on localhost, 127.x.y.z or [::1]")
}

// walletLoopbackHost is the wallet's rule for a host it answers over http (hdtp-identity's
// loopbackHost, which the wallet applies to the redirect): localhost, a dotted quad in 127.0.0.0/8
// in the normal form (four decimal octets, no leading zero), or [::1] — and no other spelling of
// loopback, such as [::ffff:7f00:1], which net.ParseIP calls loopback and the wallet refuses. The
// core does not export it; TestThePortalsLoopbackRuleIsTheWallets holds this copy to the wallet's
// answer, host by host.
func walletLoopbackHost(host string) bool {
	if host == "localhost" || host == "[::1]" {
		return true
	}
	octets := strings.Split(host, ".")
	if len(octets) != 4 || octets[0] != "127" {
		return false
	}
	for _, o := range octets {
		if o == "" || len(o) > 3 || (len(o) > 1 && o[0] == '0') {
			return false
		}
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 || strings.ContainsAny(o, "+-") {
			return false
		}
	}
	return true
}

// ask is what the GET page shows and the start handler checks: the address, the purpose, and a
// request already pending.
type walletAsk struct {
	endpoint, purpose string
	pending           *store.Leaf
}

func (d WalletDeps) prepare(w http.ResponseWriter, r *http.Request, a store.Account) (walletAsk, bool) {
	endpoint := ""
	if d.Endpoint != nil {
		endpoint = d.Endpoint(a.Slug)
	}
	if endpoint == "" {
		http.Error(w, "This node has no public URL yet, so there is no address to ask a certificate for. Set it in Settings.", http.StatusConflict)
		return walletAsk{}, false
	}
	if _, err := walletPortalOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return walletAsk{}, false
	}
	purpose, err := d.Purpose(r, a.ID, endpoint)
	if errors.Is(err, identity.ErrLeafRefused) {
		http.Error(w, "The web wallet renews and moves an identity it already certified; a first certificate comes from the command-line wallet: "+
			"`hdtp-gateway account csr -slug "+a.Slug+"`, `hdtp id issue`, `hdtp-gateway account install-leaf -slug "+a.Slug+"`.", http.StatusConflict)
		return walletAsk{}, false
	}
	if err != nil {
		http.Error(w, "could not read this identity's certificate state", http.StatusInternalServerError)
		return walletAsk{}, false
	}
	leaves, err := d.Store.ListLeaves(r.Context(), a.ID)
	if err != nil {
		http.Error(w, "could not read this identity's certificate state", http.StatusInternalServerError)
		return walletAsk{}, false
	}
	ask := walletAsk{endpoint: endpoint, purpose: purpose}
	for i := range leaves {
		if leaves[i].State == identity.LeafPending {
			ask.pending = &leaves[i]
		}
	}
	return ask, true
}

// getWallet serves `GET /identity/{slug}/wallet`: what would be asked, of which wallet, and whether
// a request is already waiting. It mints nothing and writes nothing.
func (d WalletDeps) getWallet(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	// Signed out: to sign-in, and back here after (the page is the link an import and a move
	// notice give). Signed in as somebody who does not administer it stays a 404 (walletAccount).
	if OwnerFrom(r.Context()) == "" {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
		return
	}
	a, ok := d.walletAccount(w, r)
	if !ok {
		return
	}
	ask, ok := d.prepare(w, r, a)
	if !ok {
		return
	}
	csrf := ""
	if c, err := r.Cookie(csrfCookieName()); err == nil {
		csrf = c.Value
	}
	data := map[string]any{
		"Name": a.DisplayName, "Slug": a.Slug, "Endpoint": ask.endpoint, "Purpose": ask.purpose,
		"Wallet": d.WalletOrigin, "CSRF": csrf,
	}
	if ask.pending != nil {
		data["Pending"] = agoWords(d.now().Sub(time.Unix(ask.pending.CreatedAt, 0)))
		data["PendingWallet"] = ask.pending.WalletOrigin
	}
	_ = walletAskTmpl.Execute(w, data)
}

// postWalletStart serves `POST /identity/{slug}/wallet/start`: it mints the request and answers
// with the page that sends it. A request already pending is replaced only when the form says so.
func (d WalletDeps) postWalletStart(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	a, ok := d.walletAccount(w, r)
	if !ok {
		return
	}
	ask, ok := d.prepare(w, r, a)
	if !ok {
		return
	}
	if ask.pending != nil && r.PostFormValue("replace") != "1" {
		d.audit("account_csr", "account:"+a.ID+" slug:"+a.Slug+" wallet_origin:"+d.WalletOrigin+" reason:pending", "refused")
		http.Error(w, "A request is already waiting for a wallet. Open this page again to see it, and confirm to replace it.", http.StatusConflict)
		return
	}
	origin, _ := walletPortalOrigin(r) // prepare checked it
	res, err := d.Mint(r, a, ask.purpose, ask.endpoint, d.WalletOrigin)
	switch {
	case errors.Is(err, store.ErrAddressVacated):
		http.Error(w, "That address was left by an identity whose last certificate has not expired yet; it cannot be asked for until then.", http.StatusConflict)
		return
	case errors.Is(err, identity.ErrLeafRefused):
		http.Error(w, "A web wallet signs a renewal or a move of an identity it already certified; this request is neither.", http.StatusConflict)
		return
	case err != nil:
		// Never the error's text: it can name a database, a path or a key. The audit trail has the
		// request, as account_csr `error` (cli/leafservice.go).
		http.Error(w, "The request could not be made; try again. The audit trail records the attempt (account_csr, error).", http.StatusInternalServerError)
		return
	}
	redirect := origin + "/wallet/return?slug=" + url.QueryEscape(a.Slug)
	fields := []walletField{
		{"csr", hdtpidentity.B64url(res.CSR)},
		{"purpose", res.Purpose},
		{"expect_root", a.RootFingerprint},
	}
	if len(a.RootCert) > 0 {
		fields = append(fields, walletField{"root_cert", hdtpidentity.B64url(a.RootCert)})
	}
	fields = append(fields,
		walletField{"redirect", redirect},
		walletField{"state", res.State},
		walletField{"recipient", walletRecipient(res.Endpoint)},
		walletField{"valid_days", strconv.Itoa(walletSuggestedDays)},
		walletField{"expires", d.now().Add(walletRequestLifetime).UTC().Format(time.RFC3339)},
	)
	// This page, and only this one, lets its form go to the wallet, and sends the portal's origin
	// with it: under the portal's no-referrer a cross-origin POST's Origin is `null`, which a
	// wallet refuses (HDTP §9.1).
	h := w.Header()
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Content-Security-Policy", walletFormCSP(d.WalletOrigin))
	_ = walletSubmitTmpl.Execute(w, map[string]any{
		"Action": d.WalletOrigin + "/sign", "Fields": fields, "Wallet": d.WalletOrigin,
	})
}

// walletFormCSP is the portal's policy with the wallet's origin added to form-action.
func walletFormCSP(walletOrigin string) string {
	return strings.Replace(portalCSP, "form-action 'self'", "form-action 'self' "+walletOrigin, 1)
}

// walletRecipient is what the host calls itself in the request, shown by the wallet as the host's
// own claim (at most 200 characters).
func walletRecipient(endpoint string) string {
	who := "hdtp-gateway"
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		who = "hdtp-gateway at " + u.Host
	}
	if r := []rune(who); len(r) > 200 {
		who = string(r[:200])
	}
	return who
}

// getWalletReturn serves `GET /wallet/return`: the page the wallet navigates back to. It holds no
// data; its script reads the answer from the fragment, clears it, and POSTs it same-site.
func (d WalletDeps) getWalletReturn(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	_ = walletReturnTmpl.Execute(w, map[string]any{"Cookie": csrfCookieName(), "Stylesheet": portalStylesheet})
}

// parseWalletChain reads `chain=<leaf>.<root>`, each base64url DER.
func parseWalletChain(s string) ([][]byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return nil, errors.New("the chain is two certificates, leaf then root")
	}
	var out [][]byte
	for _, p := range parts {
		b, err := hdtpidentity.DecodeB64url(p)
		if err != nil || len(b) == 0 {
			return nil, errors.New("the chain is not base64url DER")
		}
		out = append(out, b)
	}
	return out, nil
}

func walletJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// postWalletInstall serves `POST /identity/{slug}/wallet/install`. Every answer is JSON; a refusal is
// {"error": a sentence, "code": one of walletRefusals}, which the return page words for the owner.
// (No session is refused before this handler, 401, and a failed CSRF check 403, both as text.)
func (d WalletDeps) postWalletInstall(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	refuse := func(status int, code, msg string) {
		walletJSON(w, status, map[string]string{"error": msg, "code": code})
	}
	a, err := d.Store.GetAccountBySlug(r.Context(), r.PathValue("slug"))
	if err != nil || !ownerAdmins(r, d.Store, a.ID) {
		refuse(http.StatusNotFound, "not_found", "no such identity")
		return
	}
	state := r.PostFormValue("state")
	chain, err := parseWalletChain(r.PostFormValue("chain"))
	if err != nil || state == "" {
		d.audit("account_leaf_install_refused", "account:"+a.ID+" slug:"+a.Slug+" reason:malformed", "refused")
		msg := "the answer carries no state"
		if err != nil {
			msg = err.Error()
		}
		refuse(http.StatusBadRequest, "malformed", msg)
		return
	}
	res, err := d.Install(r, a, chain, state)
	if err != nil {
		status, code, msg := walletRefusal(err)
		refuse(status, code, msg)
		return
	}
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	walletJSON(w, http.StatusOK, map[string]any{
		"name": a.DisplayName, "endpoint": res.Endpoint,
		"not_before": res.NotBefore.UTC().Format(time.RFC3339), "not_after": res.NotAfter.UTC().Format(time.RFC3339),
		"notice": res.Notice, "warnings": warnings,
	})
}

// walletRefusals are the codes an install answers besides "not_found" and "malformed", each with
// its status and sentence. A state refusal is 409 (the request is not in the state the answer
// assumes); a chain refusal 400. TestEveryWalletRefusalIsWordedOnTheReturnPage holds the return
// page to this list.
var walletRefusals = []struct {
	is     error
	status int
	code   string
	msg    string
}{
	{identity.ErrRequestAnswered, http.StatusConflict, "answered", "this answer was installed already"},
	{identity.ErrNoRequest, http.StatusConflict, "no_request", "no request is waiting for a wallet's answer"},
	{identity.ErrRequestState, http.StatusConflict, "not_this_request", "this answer is not for the request waiting here"},
	{identity.ErrWrongRoot, http.StatusBadRequest, "wrong_root", "the certificate was signed by another root than this identity's"},
	{identity.ErrWrongKey, http.StatusBadRequest, "wrong_key", "the certificate is for another key than the one this node asked for"},
	{identity.ErrNotNewer, http.StatusBadRequest, "not_newer", "the certificate is not newer than the current one"},
}

// walletRefusal maps an install's error to its answer. A chain refusal the list does not name keeps
// its text, which names the rule and never a secret (identity.installLeaf); a failure of this node
// never does.
func walletRefusal(err error) (int, string, string) {
	for _, rf := range walletRefusals {
		if errors.Is(err, rf.is) {
			return rf.status, rf.code, rf.msg
		}
	}
	if errors.Is(err, identity.ErrLeafRefused) {
		msg := strings.TrimSuffix(strings.TrimPrefix(err.Error(), "identity: "), ": "+identity.ErrLeafRefused.Error())
		return http.StatusBadRequest, "chain", msg
	}
	return http.StatusInternalServerError, "failed", "the certificate could not be installed"
}

// agoWords says how long ago, in words ("4 minutes ago"), not as a Go duration ("4m0s ago"), which is
// what the replace notice printed.
func agoWords(d time.Duration) string {
	switch m := int(d.Round(time.Minute) / time.Minute); {
	case m < 1:
		return "moments ago"
	case m == 1:
		return "a minute ago"
	case m < 60:
		return fmt.Sprintf("%d minutes ago", m)
	case m < 120:
		return "an hour ago"
	default:
		return fmt.Sprintf("%d hours ago", m/60)
	}
}

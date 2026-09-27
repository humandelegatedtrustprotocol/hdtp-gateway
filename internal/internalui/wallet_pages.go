package internalui

// The signing request to a web wallet (PACT §9.1; the identity-boundary design §2): the portal asks
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
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// WalletInstalled is what an install did, as the return page reports it.
type WalletInstalled struct {
	Endpoint string
	NotAfter time.Time
	// Notice is the move notice (identity.MoveNotice), "" when the identity did not move.
	Notice string
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

// The validity a request suggests; the person chooses in the wallet (PACT §9.1).
const walletSuggestedDays = 365

//go:embed wallet_submit.js
var walletSubmitJS []byte

//go:embed wallet_return.js
var walletReturnJS []byte

const walletStyle = `<style>
 body{margin:0;background:#fafaf8;color:#1b2422;font:16px/1.6 system-ui,sans-serif}
 @media (prefers-color-scheme:dark){body{background:#0f1614;color:#e7ece8}}
 main{max-width:640px;margin:0 auto;padding:32px 24px}
 dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px}
 dd{margin:0;word-break:break-all}
 button{font:inherit;padding:8px 16px;border-radius:8px;border:1px solid #6b7a74;cursor:pointer}
 .muted{opacity:.7;font-size:14px} .err{color:#b3261e} .ok{color:#1e7a46}
</style>`

var walletAskTmpl = template.Must(template.New("ask").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sign with my web wallet</title>` + walletStyle + `</head>
<body><main>
<h1>Sign with my web wallet</h1>
<p>This node asks your wallet for a certificate for <strong>{{.Name}}</strong>. The wallet shows what it
names and asks for your passkey before it signs; nothing is signed from here.</p>
<dl><dt>Address</dt><dd>{{.Endpoint}}</dd><dt>Kind</dt><dd>{{.Purpose}}</dd><dt>Wallet</dt><dd>{{.Wallet}}</dd></dl>
{{if .Pending}}<p class="err">A request made {{.Pending}} is waiting for a wallet{{if .PendingWallet}} ({{.PendingWallet}}){{else}} (handed over by the command line){{end}}.
Continuing replaces it: a wallet's answer to that one will then be refused.</p>{{end}}
<form method="post" action="/identity/{{.Slug}}/wallet/start">
<input type="hidden" name="csrf" value="{{.CSRF}}"/>
{{if .Pending}}<input type="hidden" name="replace" value="1"/>{{end}}
<button type="submit">{{if .Pending}}Replace it and continue to my wallet{{else}}Continue to my wallet{{end}}</button>
</form>
<p class="muted">The wallet sends its answer back to this node's /wallet/return, in this browser.</p>
</main></body></html>`))

var walletSubmitTmpl = template.Must(template.New("submit").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Opening your wallet</title>` + walletStyle + `</head>
<body><main>
<h1>Opening your wallet…</h1>
<form id="wallet-form" method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}"/>
{{end}}<button type="submit">Continue to {{.Wallet}}</button>
</form>
<script src="/wallet/submit.js"></script>
</main></body></html>`))

var walletReturnTmpl = template.Must(template.New("return").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="pact-csrf-cookie" content="{{.Cookie}}"/>
<title>Your wallet's answer</title>` + walletStyle + `</head>
<body><main>
<h1>Your wallet's answer</h1>
<p id="out">Installing…</p>
<noscript><p class="err">Installing the certificate needs this page's script.</p></noscript>
<p><a href="/identity">Back to Identity</a></p>
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
	h := u.Hostname()
	if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
		return o, nil
	}
	return "", errors.New("this portal is served over http at an address that is not this machine; a web wallet sends its answer only to https, or to http on localhost")
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
			"`pact-gateway account csr -slug "+a.Slug+"`, `pact id issue`, `pact-gateway account install-leaf -slug "+a.Slug+"`.", http.StatusConflict)
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
		data["Pending"] = d.now().Sub(time.Unix(ask.pending.CreatedAt, 0)).Round(time.Minute).String() + " ago"
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
	if err != nil {
		http.Error(w, "could not make the request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	redirect := origin + "/wallet/return?slug=" + url.QueryEscape(a.Slug)
	fields := []walletField{
		{"csr", pactidentity.B64url(res.CSR)},
		{"purpose", res.Purpose},
		{"expect_root", a.RootFingerprint},
	}
	if len(a.RootCert) > 0 {
		fields = append(fields, walletField{"root_cert", pactidentity.B64url(a.RootCert)})
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
	// wallet refuses (PACT §9.1).
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
	who := "pact-gateway"
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		who = "pact-gateway at " + u.Host
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
	_ = walletReturnTmpl.Execute(w, map[string]any{"Cookie": csrfCookieName()})
}

// parseWalletChain reads `chain=<leaf>.<root>`, each base64url DER.
func parseWalletChain(s string) ([][]byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return nil, errors.New("the chain is two certificates, leaf then root")
	}
	var out [][]byte
	for _, p := range parts {
		b := pactidentity.FromB64url(p)
		if len(b) == 0 {
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

// postWalletInstall serves `POST /identity/{slug}/wallet/install`.
func (d WalletDeps) postWalletInstall(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	a, err := d.Store.GetAccountBySlug(r.Context(), r.PathValue("slug"))
	if err != nil || !ownerAdmins(r, d.Store, a.ID) {
		walletJSON(w, http.StatusNotFound, map[string]string{"error": "no such identity"})
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
		walletJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	res, err := d.Install(r, a, chain, state)
	switch {
	case errors.Is(err, identity.ErrRequestState):
		walletJSON(w, http.StatusConflict, map[string]string{"error": "this answer is not for the request waiting here, or it was installed already"})
		return
	case errors.Is(err, identity.ErrLeafRefused):
		walletJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	case err != nil:
		walletJSON(w, http.StatusInternalServerError, map[string]string{"error": "the certificate could not be installed"})
		return
	}
	walletJSON(w, http.StatusOK, map[string]string{
		"endpoint": res.Endpoint, "not_after": res.NotAfter.UTC().Format(time.RFC3339), "notice": res.Notice,
	})
}

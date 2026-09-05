package internalui

// Invite landing page (SPEC §9.2), served on the PUBLIC listener at /i/{token}:
// a human-readable page carrying the issuer's SIGNED card and a QR of the invite
// URL — the guest holds the card BEFORE redeeming, which is also what makes sealed
// redemption toward a required issuer possible (PACT §13.2). Unknown, revoked,
// expired, and exhausted tokens are all the SAME 404: the page must not be an
// oracle for invite state.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// CardSigner produces the issuer's card text and its signature for an account —
// implemented by identity.Manager (SPEC §9.3); injected to keep packages apart.
type CardSigner func(accountID string) (cardText string, sigB64 string, err error)

type LandingDeps struct {
	Store    store.Store
	SignCard CardSigner
	// SPKI returns the issuer's public key (SubjectPublicKeyInfo DER). A card
	// carries only the key's HASH, so a redeemer that must SEAL its
	// `redeem_invite` toward a `seal: required` issuer (edge mode forces it)
	// cannot proceed on the card alone. The key therefore travels with the card
	// on this page — the pre-redemption trust channel the issuer handed over —
	// and the redeemer verifies it by hashing to `X-PACT-KEY` before use.
	// identity.Manager.AccountSPKI implements it; nil omits the field.
	SPKI func(accountID string) ([]byte, error)
	// PublicURL is the externally reachable base invite links are built from
	// (PublicURL + /i/ + token; "" = relative). It is a FUNC, not a string,
	// because the owner can change the public URL while the node serves: a
	// captured value would keep printing links at the old host while the card
	// advertises the new one.
	PublicURL func() string
	Now       func() time.Time
}

var landingTmpl = template.Must(template.New("landing").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>PACT invite</title>
<style>
 body{margin:0;background:#fafaf8;color:#1b2422;font:16px/1.6 system-ui,sans-serif}
 @media (prefers-color-scheme:dark){body{background:#0f1614;color:#e7ece8}}
 main{max-width:640px;margin:0 auto;padding:32px 24px}
 .card{border:1px solid #d9ded8;border-radius:12px;padding:24px;margin:16px 0}
 pre{white-space:pre-wrap;word-break:break-all;font:13px/1.5 ui-monospace,monospace}
 img{max-width:200px;height:auto}
 .muted{opacity:.7;font-size:14px}
</style>
</head>
<body><main>
<h1>{{.FN}} invites your agent to connect</h1>
<p>This is a <strong>PACT</strong> invite. Point your agent at it — redemption pins the
card below, so verify it came from the person you expect before connecting.</p>
<div class="card"><h2>Their signed card</h2><pre>{{.Card}}</pre>
<p class="muted">signature (by the key the card names): <code>{{.Sig}}</code></p>
{{if .SPKI}}<p class="muted">public key (SubjectPublicKeyInfo, base64url DER — hash it to check it matches X-PACT-KEY above): <code>{{.SPKI}}</code></p>{{end}}</div>
<div class="card"><h2>Share</h2><img src="{{.QR}}" alt="QR of this invite link"/></div>
<p class="muted">pact-gateway serves this page self-contained: no external assets, no telemetry.</p>
</main></body></html>`))

// LandingHandler renders /i/{token}.
func LandingHandler(d LandingDeps) http.Handler {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if token == "" {
			http.NotFound(w, r)
			return
		}
		sum := sha256.Sum256([]byte(token))
		inv, err := d.Store.GetInviteByHashGlobal(r.Context(), sum[:])
		// One indistinguishable 404 for unknown, revoked, expired, exhausted.
		if err != nil || inv.RevokedAt != 0 || inv.Uses >= inv.MaxUses || now().Unix() >= inv.ExpiresAt {
			http.NotFound(w, r)
			return
		}
		card, sig, err := d.SignCard(inv.AccountID)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		a, err := d.Store.GetAccountByID(r.Context(), inv.AccountID)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var spkiB64 string
		if d.SPKI != nil {
			if spki, err := d.SPKI(inv.AccountID); err == nil {
				spkiB64 = base64.RawURLEncoding.EncodeToString(spki)
			}
		}
		// Machine view: a redeeming agent needs card + key + signature, not HTML.
		if wantsJSON(r) {
			w.Header().Set("Content-Type", "application/pact-invite+json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"card": card, "card_sig": sig, "spki": spkiB64,
			})
			return
		}
		base := ""
		if d.PublicURL != nil {
			base = d.PublicURL()
		}
		link := base + "/i/" + token
		png, err := qrcode.Encode(link, qrcode.Medium, 256)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = landingTmpl.Execute(w, map[string]any{
			"FN":   a.DisplayName,
			"Card": card,
			"Sig":  sig,
			"SPKI": spkiB64,
			// #nosec G203 -- a data: URI over base64 of a PNG this handler just
			// rendered; no part of it is caller-supplied.
			"QR": template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		})
	})
}

// wantsJSON is true for agents asking for the machine view.
func wantsJSON(r *http.Request) bool {
	a := r.Header.Get("Accept")
	return r.URL.Query().Get("format") == "json" ||
		strings.Contains(a, "application/json") || strings.Contains(a, "application/pact-invite+json")
}

var _ = fmt.Sprintf // reserved for future use in error paths

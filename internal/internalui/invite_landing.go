package internalui

// Invite landing page (SPEC §9.2), served on the PUBLIC listener at /i/{token}:
// a human-readable page carrying the issuer's SIGNED card and a QR of the invite
// URL — the guest holds the card BEFORE redeeming, which is also what makes sealed
// redemption toward a required issuer possible (HDTP §13.2). Unknown, revoked,
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

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	hdtpidentity "github.com/pact-cloud/pact-identity/go"
)

// LandingDeps is what the landing page reads. Its fields are node.LandingDeps' exactly, so the one
// converts to the other: the node builds it, and `serve` hands this package's page to the node.
type LandingDeps struct {
	Store store.Store
	// SignCard produces the issuer's card text and its signature for an account (SPEC §9.3).
	SignCard func(accountID string) (cardText string, sigB64 string, err error)
	// Chain returns the issuer's [leaf, root]. HDTP §4: the machine view is exactly
	// {card, card_sig, chain}, and the chain is what a redeemer validates before it seals its
	// first call — so a landing that cannot produce one has nothing redeemable to serve.
	Chain func(accountID string) ([][]byte, error)
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
<title>HDTP invite</title>
` + landingStyle + `
</head>
<body><main>
<div class="brand">` + landingMark + `<span>HDTP</span></div>
<h1>{{.FN}} invites your agent to connect</h1>
<p>This is a <strong>HDTP</strong> invite. Point your agent at it — redemption pins the
card below, so verify it came from the person you expect before connecting.</p>
<p>Running your own HDTP node? Paste this page's address into your node's portal, under
<strong>People → Accept an invite</strong>.</p>
<div class="card"><h2>Their signed card</h2><pre>{{.Card}}</pre>
<p class="muted">signature (by the key the card names): <code>{{.Sig}}</code></p>
</div>
<div class="card"><h2>Share</h2><img src="{{.QR}}" alt="QR of this invite link"/></div>
<p class="muted">hdtp-gateway serves this page self-contained: no external assets, no telemetry.</p>
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
		// Machine view (HDTP §4): exactly the signed card and the chain that proves it. The
		// chain is not optional. It used to be added "if there is one", beside a `spki` member
		// the spec does not define, so an issuer with no chain served an offer nobody could
		// redeem and said nothing; now it says it is unavailable.
		if wantsJSON(r) {
			if d.Chain == nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			chain, err := d.Chain(inv.AccountID)
			if err != nil || len(chain) != 2 {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/hdtp-invite+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"card": card, "card_sig": sig,
				"chain": []string{hdtpidentity.B64url(chain[0]), hdtpidentity.B64url(chain[1])},
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
		strings.Contains(a, "application/json") || strings.Contains(a, "application/hdtp-invite+json")
}

var _ = fmt.Sprintf // reserved for future use in error paths

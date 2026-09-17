package internalui

// The dashboard (SPEC §8.2): at-a-glance node state and recent activity.
//
// What it shows is chosen to answer the questions an owner actually has when
// they open the portal: is this node reachable, what is it enforcing, who can
// reach it, and what has happened lately. In particular it shows the resolved
// deployment posture rather than the configured one — an edge adapter forces
// `seal: required` and `client_cert: off`, and the value that matters is the one
// in effect, not the one someone typed.
//
// It replaces the first-run shell but not the first-run behaviour: with no
// passkey registered, the page still leads to the setup wizard, because that is
// the §8.3 gate and skipping it would leave a node anyone could claim.

import (
	"context"
	"net/http"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// DashboardDeps is the state the page reports.
type DashboardDeps struct {
	Store store.Store
	// Posture is the resolved deployment state — what is in effect now.
	Posture func() DashboardPosture
	// Recent returns the newest audit rows, most recent first.
	Recent func(ctx context.Context, limit int) ([]store.AuditRow, error)
	// Setup gates the first-run wizard this page auto-shows at zero passkeys.
	Setup *SetupTokens
	// SignedIn reports whether this request carries a portal session. Nil means
	// no authentication is configured — a loopback portal serves with no login
	// (SPEC §8.3), and offering to sign out of a session that does not exist
	// promises something the button cannot do.
	SignedIn func(*http.Request) bool
}

// DashboardPosture is the resolved node state.
type DashboardPosture struct {
	Mode       string `json:"mode"`
	Seal       string `json:"seal"`
	ClientCert string `json:"client_cert"`
	Tunnel     string `json:"tunnel"`
	PublicURL  string `json:"public_url"`
}

type dashAccount struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Fingerprint string `json:"fingerprint"`
	Contacts    int    `json:"contacts"`
	Pending     int    `json:"pending"`
}

// MountDashboard serves the dashboard DATA at /api/dashboard; the SPA renders
// it. The §8.3 zero-passkey rule is reported as `needs_setup` (via /api/session
// too) and the SPA routes to the wizard — the gate that matters still guards
// /setup/begin and /setup/finish server-side, so auto-showing the wizard remains
// presentation, not permission.
func MountDashboard(mux *http.ServeMux, d DashboardDeps) {
	mux.HandleFunc("GET /api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		accounts, err := d.Store.ListAccounts(r.Context())
		if err != nil {
			http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
			return
		}
		rows := make([]dashAccount, 0, len(accounts))
		for _, a := range accounts {
			list, _ := d.Store.ListContacts(r.Context(), a.ID)
			active, pending := 0, 0
			for _, c := range list {
				switch c.Status {
				case "active":
					active++
				case "pending_in":
					pending++
				}
			}
			rows = append(rows, dashAccount{
				Slug: a.Slug, DisplayName: a.DisplayName, Fingerprint: a.Fingerprint,
				Contacts: active, Pending: pending,
			})
		}
		var recent []store.AuditRow
		if d.Recent != nil {
			recent, _ = d.Recent(r.Context(), 10)
		}
		posture := DashboardPosture{}
		if d.Posture != nil {
			posture = d.Posture()
		}
		apiJSON(w, map[string]any{"posture": posture, "accounts": rows, "recent": recent})
	})
}

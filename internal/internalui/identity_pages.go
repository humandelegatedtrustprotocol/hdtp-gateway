package internalui

// Settings · identity (SPEC §8.2): an account's identity and certificate, from
// the portal.
//
// Rotation used to be CLI-only. It is routine key hygiene, and requiring shell
// access for it is the kind of gap that means it never gets done — the same
// reasoning that already puts passkey removal on this surface.
//
// It is guarded by typing the account slug rather than by a bare button, because
// it is consequential and not undoable: every active contact is sent an
// `update_contact` signed by the OLD key, and any contact that never receives it
// has to re-pin by hand. A misclick should not be able to start that.

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// IdentityDeps is what the identity page needs.
type IdentityDeps struct {
	Accounts func(ctx context.Context) ([]store.Account, error)
	// Create provisions a new identity, running the SAME procedure `account
	// create` does — a portal that generated keys its own way would be a second
	// identity path to keep in step. Nil hides the affordance rather than
	// offering a button that cannot work.
	Create func(ctx context.Context, slug, displayName, algo string) (store.Account, error)
	Audit  func(action, resource, outcome string)
	// Certificate reports a 2.0 account's leaf (PACT §2): the root that is
	// the identity, the endpoint, the dates, and whether renewal is due —
	// the thirty-day prompt a host owes the person. nil hides the columns.
	Certificate func(ctx context.Context, accountID string) (identity.CertificateInfo, error)
}

func (d IdentityDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// identityRow is one account as the portal renders it.
type identityRow struct {
	Slug            string `json:"slug"`
	DisplayName     string `json:"display_name"`
	Fingerprint     string `json:"fingerprint"`
	Algo            string `json:"algo"`
	ID              string `json:"id"`
	RootFingerprint string `json:"root_fingerprint,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	NotAfter        string `json:"not_after,omitempty"`
	RenewalDue      bool   `json:"renewal_due,omitempty"`
}

func MountIdentityPages(mux *http.ServeMux, d IdentityDeps) {
	render := func(w http.ResponseWriter, r *http.Request, notice, errMsg string) {
		accts, err := d.Accounts(r.Context())
		if err != nil {
			http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
			return
		}
		rows := []identityRow{}
		for _, a := range accts {
			row := identityRow{
				ID: a.ID, Slug: a.Slug, DisplayName: a.DisplayName,
				Algo: a.Algo, Fingerprint: a.Fingerprint,
			}
			if a.HasRoot() && d.Certificate != nil {
				if info, err := d.Certificate(r.Context(), a.ID); err == nil && info.Certified {
					row.RootFingerprint, row.Endpoint = info.RootFingerprint, info.Endpoint
					row.NotAfter, row.RenewalDue = info.NotAfter.UTC().Format(time.RFC3339), info.RenewalDue
				}
			}
			rows = append(rows, row)
		}
		apiJSON(w, map[string]any{
			"rows": rows, "notice": notice, "error": errMsg,
			"can_create": d.Create != nil,
		})
	}

	mux.HandleFunc("GET /api/identity", func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "", "")
	})

	// A second identity is how one node serves two people, or one person keeps
	// work and home apart (SPEC §3.2). It was CLI-only, which meant the portal
	// could show a switcher it gave you no way to fill.
	mux.HandleFunc("POST /identity/create", func(w http.ResponseWriter, r *http.Request) {
		if d.Create == nil {
			http.Error(w, "creating identities is not configured on this node", http.StatusServiceUnavailable)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		slug := strings.TrimSpace(r.Form.Get("slug"))
		name := strings.TrimSpace(r.Form.Get("name"))
		if slug == "" || name == "" {
			render(w, r, "", "An identity needs both a slug and a display name.")
			return
		}
		a, err := d.Create(r.Context(), slug, name, r.Form.Get("algo"))
		if err != nil {
			d.audit("account_create", "slug:"+slug, "error")
			render(w, r, "", "Could not create that identity: "+err.Error())
			return
		}
		d.audit("account_create", "account:"+a.ID+" slug:"+a.Slug, "ok")
		render(w, r, "Created "+a.DisplayName+" ("+a.Slug+"). It is servable now — no restart.", "")
	})

}

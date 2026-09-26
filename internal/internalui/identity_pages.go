package internalui

// Settings · identity (SPEC §8.2): an account's identity and certificate, from
// the portal.
//
// What it shows is each identity's root, the endpoint its leaf names, the leaf's
// notAfter and whether a renewal is due; what it does is create a second identity.
// There is nothing here to rotate: the identity is a root this node does not hold,
// and a leaf is replaced by the wallet signing a new one. This header described a
// slug-guarded rotation button, and an `update_contact` "signed by the OLD key", for
// as long after 1.x went as it took somebody to read it.

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
	// Certificate reports an account's leaf (PACT §2): the root that is
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

	mux.HandleFunc("GET /api/identity", d.getAPIIdentity(render))
	mux.HandleFunc("POST /identity/create", d.postIdentityCreate(render))

}

// getAPIIdentity serves `GET /api/identity`.
func (d IdentityDeps) getAPIIdentity(render func(w http.ResponseWriter, r *http.Request, notice string, errMsg string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "", "")
	}
}

// postIdentityCreate serves `POST /identity/create`.
//
// A second identity is how one node serves two people, or one person keeps
// work and home apart (SPEC §3.2). It was CLI-only, which meant the portal
// could show a switcher it gave you no way to fill.
func (d IdentityDeps) postIdentityCreate(render func(w http.ResponseWriter, r *http.Request, notice string, errMsg string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
		// Not "servable now". It said that, and a new identity is not: it has a key and no
		// certificate, and answers nobody until its wallet has signed one (PACT §2).
		render(w, r, "Created "+a.DisplayName+" ("+a.Slug+"). It is not served yet: run `pact-gateway account csr -slug "+a.Slug+
			"`, have your wallet sign it, then `pact-gateway account install-leaf`. No restart is needed for either.", "")
	}
}

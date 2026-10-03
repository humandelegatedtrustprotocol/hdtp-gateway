package internalui

// The dashboard (SPEC §8.2): at-a-glance node state. The audit trail is the Audit page's.
//
// What it shows is chosen to answer the questions an owner actually has when they open the portal:
// is this node reachable and what is it enforcing, and for each identity they administer — is its
// certificate current, how many people can reach it, and who is waiting for an answer. It shows the
// resolved deployment posture rather than the configured one — an edge adapter forces
// `seal: required` and `client_cert: off`, and the value that matters is the one in effect, not the
// one someone typed.
//
// Every number is read here, from the store, on each visit; none is estimated. A list the store
// could not read fails the answer rather than counting as zero: "0 waiting" for a read that failed
// tells an owner nobody is waiting.
//
// It replaces the first-run shell but not the first-run behaviour: with no passkey registered, the
// page still leads to the setup wizard, because that is the §8.3 gate and skipping it would leave a
// node anyone could claim.

import (
	"context"
	"net/http"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
)

// DashboardDeps is the state the page reports.
type DashboardDeps struct {
	Store store.Store
	// Posture is the resolved deployment state — what is in effect now.
	Posture func() DashboardPosture
	// Certificate reports an identity's certificate: the SAME reader Settings · identity renders
	// (IdentityDeps.Certificate), so the two pages cannot disagree about a leaf. Nil (a test's
	// mount) answers each identity's certificate as null.
	Certificate func(ctx context.Context, accountID string) (identity.CertificateInfo, error)
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
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Fingerprint string `json:"fingerprint"`
	// Contacts counts the active contacts: the people who can reach this identity now.
	Contacts int `json:"contacts"`
	// Pending counts what the Requests tab holds for this identity, which its "N waiting" links to:
	// the contact requests waiting for an answer and the contacts waiting at a new address.
	Pending int `json:"pending"`
	// Certificate is the identity's leaf as the certificate reader reports it; null when this node
	// has no reader wired.
	Certificate *dashCert `json:"certificate"`
}

// dashCert is an identity's certificate as the overview shows it. The flags are the reader's own —
// the page derives nothing but the days between now and NotAfter.
type dashCert struct {
	// Certified: a wallet has signed this identity (it has a root).
	Certified bool `json:"certified"`
	// Served: this host holds a current leaf for it. A certified identity can hold none: an import
	// leaves it so until the wallet signs one, and a leaf past its notAfter is retired.
	Served     bool   `json:"served"`
	Endpoint   string `json:"endpoint,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	RenewalDue bool   `json:"renewal_due"`
}

// MountDashboard serves the dashboard DATA at /api/dashboard; the SPA renders
// it. The §8.3 zero-passkey rule is reported as `needs_setup` (via /api/session
// too) and the SPA routes to the wizard — the gate that matters still guards
// /setup/begin and /setup/finish server-side, so auto-showing the wizard remains
// presentation, not permission.
func MountDashboard(mux *http.ServeMux, d DashboardDeps) {
	mux.HandleFunc("GET /api/dashboard", d.getAPIDashboard)
}

// getAPIDashboard serves `GET /api/dashboard`.
func (d DashboardDeps) getAPIDashboard(w http.ResponseWriter, r *http.Request) {
	owner := OwnerFrom(r.Context())
	if owner == "" {
		// As the audit read: the session gate guarantees an owner, and a mount without one must not
		// describe the node's identities to nobody in particular.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"identity_required"}`))
		return
	}
	rows, err := d.accounts(r.Context(), owner)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	posture := DashboardPosture{}
	if d.Posture != nil {
		posture = d.Posture()
	}
	apiJSON(w, map[string]any{"posture": posture, "accounts": rows})
}

// accounts is the overview's row for each identity this owner administers — the identities the
// switcher offers them (/api/session), and no others: the page listed every account on the node.
func (d DashboardDeps) accounts(ctx context.Context, owner string) ([]dashAccount, error) {
	admins, err := administered(ctx, d.Store, owner)
	if err != nil {
		return nil, err
	}
	accounts, err := d.Store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]dashAccount, 0, len(accounts))
	for _, a := range accounts {
		if !admins[a.ID] {
			continue
		}
		list, err := d.Store.ListContacts(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		active, pending := 0, 0
		for _, c := range list {
			switch c.Status {
			case "active":
				active++
			case "pending_in":
				pending++
			}
		}
		// The Requests tab this count links to also holds contacts waiting at a new address.
		ps, err := d.Store.ListPendingAddresses(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		pending += len(ps)
		row := dashAccount{
			ID: a.ID, Slug: a.Slug, DisplayName: a.DisplayName, Fingerprint: a.Fingerprint,
			Contacts: active, Pending: pending,
		}
		switch {
		case d.Certificate == nil:
		case !a.HasRoot():
			// No wallet has signed it: nothing to read, as Settings · identity asks the reader only of
			// an identity with a root. The reader's walk of the handshakes owed is not for one without.
			row.Certificate = &dashCert{}
		default:
			info, err := d.Certificate(ctx, a.ID)
			if err != nil {
				return nil, err
			}
			c := &dashCert{Certified: info.Certified, Served: info.Served()}
			if c.Served {
				c.Endpoint, c.NotAfter, c.RenewalDue = info.Endpoint, info.NotAfter.UTC().Format(time.RFC3339), info.RenewalDue
			}
			row.Certificate = c
		}
		rows = append(rows, row)
	}
	return rows, nil
}

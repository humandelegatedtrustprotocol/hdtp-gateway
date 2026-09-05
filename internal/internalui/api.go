package internalui

// The JSON read layer for the embedded SPA (SPEC §8.2).
//
// The portal was server-rendered; it is now a React app compiled into the
// binary, and these endpoints serve it the SAME data the templates received —
// each one lifted from the GET handler it replaces, against the same deps wired
// in cli.go. Nothing about authorization moved: the session middleware, the csrf
// double-submit and the account-scoping middleware all sit in front of /api
// exactly as they sat in front of the pages, and every WRITE still goes to the
// original POST endpoints, which are audited and tested and did not change.
//
// The one deliberate difference: an unauthenticated /api request gets 401 JSON,
// not a 303 to /login — a fetch() cannot usefully follow a login redirect, and
// the SPA routes to its own sign-in view on 401.

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// apiJSON writes one API response. Every /api payload goes through here so the
// content type and the no-store rule cannot be forgotten per endpoint: this
// surface serves contact lists and message bodies, which have no business in a
// shared cache.
func apiJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// SessionAPIDeps drives /api/session, the first call the SPA makes.
type SessionAPIDeps struct {
	Store store.Store
	// NeedsSetup reports zero registered passkeys — the §8.3 state in which the
	// portal must lead to the wizard and nowhere else.
	NeedsSetup func(ctx context.Context) bool
}

type apiAccount struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Fingerprint string `json:"fingerprint"`
}

// MountSessionAPI registers /api/session: who is here, what state the node is
// in, and which identities this owner may act as. The account list is scoped by
// the same rule the account middleware enforces — memberships — so the picker
// never offers an identity a request would then refuse.
func MountSessionAPI(mux *http.ServeMux, d SessionAPIDeps) {
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		owner := OwnerFrom(r.Context())
		// This endpoint is deliberately open — the sign-in and wizard views are
		// rendered from it before any session exists — so it must say the
		// MINIMUM. Without a session that is: whether to show sign-in, and
		// whether the node is still unclaimed. Never the identities it holds:
		// enumerating a node's accounts, their slugs and their fingerprints is
		// not something a caller who has proven nothing is owed. (It used to
		// list them all when owner was "", which was invisible while a loopback
		// portal served with no login at all.)
		out := make([]apiAccount, 0)
		if owner != "" {
			accounts, err := d.Store.ListAccounts(r.Context())
			if err != nil {
				http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
				return
			}
			ms, merr := d.Store.ListMembershipsByOwner(r.Context(), owner)
			if merr != nil {
				http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
				return
			}
			admin := map[string]bool{}
			for _, m := range ms {
				if m.Role == "admin" {
					admin[m.AccountID] = true
				}
			}
			for _, a := range accounts {
				if !admin[a.ID] {
					continue
				}
				out = append(out, apiAccount{ID: a.ID, Slug: a.Slug, DisplayName: a.DisplayName, Fingerprint: a.Fingerprint})
			}
		}
		needsSetup := d.NeedsSetup != nil && d.NeedsSetup(r.Context())
		// No `login_required`: a session is required on every bind now (§8.3),
		// so the field could only ever be true. What the shell actually needs to
		// know is whether it HAS one, and whether the node is still unclaimed.
		apiJSON(w, map[string]any{
			"signed_in":   owner != "",
			"needs_setup": needsSetup,
			"accounts":    out,
			// Which cookie names belong to THIS node. Two nodes on one host share
			// a cookie jar (cookies ignore ports), so the page has to be told
			// which csrf cookie is its own rather than taking the first match.
			// Not a secret: it is already visible as a cookie name.
			"cookie_tag": cookieTag,
		})
	})
}

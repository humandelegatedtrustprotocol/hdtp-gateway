package internalui

// Owners, passkeys and bearer tokens (SPEC §8.2 "Settings · owners", §8.6).
//
// SPEC §8.6 draws a line this page respects: passkey **registration** happens
// here and nowhere else — never over the owner MCP, because a bearer-token
// session cannot perform a WebAuthn ceremony, and the boundary also guarantees a
// token can never mint a durable credential for itself. Listing and removing are
// available on all three surfaces; only creation is portal-only.
//
// A bearer token is shown exactly once. Anything else would mean storing a
// recoverable secret, and the store deliberately keeps only its hash.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

// OwnersDeps is what Settings · owners needs: the passkeys and bearer tokens it lists, removes,
// mints and revokes.
type OwnersDeps struct {
	// Store supplies the accounts a token can be narrowed to and, with no session, the node's
	// first owner.
	Store store.Store
	// Tokens mints, lists and revokes owner-MCP bearer tokens.
	Tokens *auth.TokenService
	// Passkeys lists and removes registered passkeys.
	Passkeys func(ctx context.Context) ([]auth.PasskeyInfo, error)
	// Remove deletes a passkey by id (auth.Service.RemovePasskey, which refuses the last one).
	// Nil answers 503 from the remove route.
	Remove func(ctx context.Context, id string) error
	// Audit records the page's mutations. Nil records nothing.
	Audit func(action, resource, outcome string)
}

func (d OwnersDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

// MountOwnerPages registers Settings · owners: GET /api/owners, POST /owners/passkeys/{id}/remove,
// POST /owners/tokens/create and POST /owners/tokens/{id}/revoke. Every answer, including a
// mutation's, is the page's whole state as JSON.
func MountOwnerPages(mux *http.ServeMux, d OwnersDeps) {
	render := func(w http.ResponseWriter, r *http.Request, notice, newToken string) {
		var passkeys []auth.PasskeyInfo
		if d.Passkeys != nil {
			passkeys, _ = d.Passkeys(r.Context())
		}
		tokens, _ := d.Tokens.List(r.Context())
		accts, _ := d.Store.ListAccounts(r.Context())
		choices := make([]AccountChoice, 0, len(accts))
		for _, a := range accts {
			choices = append(choices, AccountChoice{ID: a.ID, Label: a.DisplayName + " (" + a.Slug + ")"})
		}
		apiJSON(w, map[string]any{
			"notice": notice, "new_token": newToken,
			"passkeys": passkeys, "tokens": tokens, "accounts": choices,
		})
	}

	mux.HandleFunc("GET /api/owners", d.getAPIOwners(render))
	mux.HandleFunc("POST /owners/passkeys/{id}/remove", d.postOwnersPasskeysIDRemove(render))
	mux.HandleFunc("POST /owners/tokens/create", d.postOwnersTokensCreate(render))
	mux.HandleFunc("POST /owners/tokens/{id}/revoke", d.postOwnersTokensIDRevoke(render))
}

// getAPIOwners serves `GET /api/owners`.
func (d OwnersDeps) getAPIOwners(render func(w http.ResponseWriter, r *http.Request, notice string, newToken string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "", "")
	}
}

// postOwnersPasskeysIDRemove serves `POST /owners/passkeys/{id}/remove`.
func (d OwnersDeps) postOwnersPasskeysIDRemove(render func(w http.ResponseWriter, r *http.Request, notice string, newToken string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if d.Remove == nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		// Removing the last passkey would lock the owner out with no way back
		// except the CLI, and zero passkeys re-opens the setup wizard. The
		// invariant is enforced in auth.Service as one statement — this page
		// only reports it, because a check here could race the owner MCP.
		if err := d.Remove(r.Context(), id); err != nil {
			if errors.Is(err, auth.ErrLastPasskey) {
				d.audit("passkey_remove", "passkey:"+id, "refused_last")
				render(w, r, "That is the only passkey registered. Register another before removing it, "+
					"or you would have no way back into this portal.", "")
				return
			}
			d.audit("passkey_remove", "passkey:"+id, "error")
			render(w, r, "could not remove that passkey", "")
			return
		}
		d.audit("passkey_remove", "passkey:"+id, "ok")
		render(w, r, "Passkey removed.", "")
	}
}

// postOwnersTokensCreate serves `POST /owners/tokens/create`.
func (d OwnersDeps) postOwnersTokensCreate(render func(w http.ResponseWriter, r *http.Request, notice string, newToken string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		label := strings.TrimSpace(r.PostForm.Get("label"))
		owner := OwnerFrom(r.Context())
		if owner == "" {
			// With no session in the context the token belongs to the node's
			// first owner; with none registered there is nobody to issue for.
			owners, err := d.Store.ListOwners(r.Context())
			if err != nil || len(owners) == 0 {
				render(w, r, "register a passkey first — a token belongs to an owner", "")
				return
			}
			owner = owners[0].ID
		}
		scope := r.PostForm.Get("account")
		// A node-wide token has no account; a dangling "account:" prefix would
		// carry junk and satisfy the attribution lint without saying anything.
		attributed := func(rest string) string {
			if scope == "" {
				return rest
			}
			return "account:" + scope + " " + rest
		}
		plain, id, err := d.Tokens.Create(r.Context(), owner, label, scope)
		if err != nil {
			d.audit("token_create", attributed("owner:"+owner), "error")
			render(w, r, "could not create that token: "+err.Error(), "")
			return
		}
		// The id is audited; the token itself never is.
		d.audit("token_create", attributed("token:"+id+" owner:"+owner), "ok")
		render(w, r, "", plain)
	}
}

// postOwnersTokensIDRevoke serves `POST /owners/tokens/{id}/revoke`.
func (d OwnersDeps) postOwnersTokensIDRevoke(render func(w http.ResponseWriter, r *http.Request, notice string, newToken string)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := d.Tokens.Revoke(r.Context(), id); err != nil {
			d.audit("token_revoke", "token:"+id, "error")
			render(w, r, "could not revoke that token", "")
			return
		}
		d.audit("token_revoke", "token:"+id, "ok")
		render(w, r, "Token revoked. Any session using it stops now.", "")
	}
}

package internalui

// Management pages (SPEC §8.2): contact-request approvals, invite lifecycle, and
// the card builder with .vcf export. Every mutation audits.

import (
	"context"
	"fmt"
	"net/http"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

type ManageDeps struct {
	Store    store.Store
	Contacts *contacts.Manager
	Audit    func(action, resource, outcome string)
	// Invalidate drops and recomposes a caller's live tool surface. Approving a
	// request changes their tier; without this the pool keeps serving the
	// surface it composed when they first called — the guest one — and an
	// approved contact is refused every tool they were just granted. The owner
	// MCP's approve_contact always did this; the portal's approve did not, which
	// is why the harness (owner MCP) passed while a person approving in the UI
	// got permission_denied on the very next message.
	Invalidate Invalidator
	// Card renders the account's card. It MUST be the same function the public
	// surface serves from (node.Card): a portal that builds its own card can
	// show the owner something peers never receive — a stale endpoint, or a seal
	// policy the gate does not enforce. Nil falls back to a local build from
	// PublicURL, which is for tests only.
	Card func(ctx context.Context, accountID string) (string, error)
	// PublicURL is a FUNC, like Card, because the owner can change it in Settings
	// while the node serves: a value captured once at wiring time is stale from
	// the first change. It was also never wired at all, so an invite rendered as
	// a bare `/i/<token>` path that nobody could open.
	PublicURL func() string
	// SignCard yields the account's card signature (identity.Manager.SignCard).
	SignCard func(accountID, cardText string) (string, error)
	// Approved tells the peer their request was accepted (`contact_accepted`).
	// Without it the approval is local only and they sit at pending_out forever.
	// Nil skips the call; the approval still stands.
	Approved func(ctx context.Context, accountID, contactFpr string, granted []string) error
}

// publicURL is the node's externally reachable base, or "" when none is set.
func (d ManageDeps) publicURL() string {
	if d.PublicURL == nil {
		return ""
	}
	return d.PublicURL()
}

func (d ManageDeps) buildCard(r *http.Request, accountID string) (string, store.Account, error) {
	a, err := d.Store.GetAccountByID(r.Context(), accountID)
	if err != nil {
		return "", a, err
	}
	if d.Card != nil {
		card, err := d.Card(r.Context(), accountID)
		return card, a, err
	}
	endpoint := ""
	if base := d.publicURL(); base != "" {
		endpoint = base + "/a/" + a.Slug + "/mcp"
	}
	card, err := contacts.BuildCard(contacts.Card{
		FN: a.DisplayName, Endpoint: endpoint, Key: a.Fingerprint, Seal: a.Seal,
	})
	return card, a, err
}

func MountManagePages(mux *http.ServeMux, d ManageDeps) {

	mux.HandleFunc("GET /api/requests", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		list, err := d.Store.ListContacts(r.Context(), account)
		if err != nil {
			http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
			return
		}
		type row struct {
			Fingerprint string `json:"fingerprint"`
			DisplayName string `json:"display_name"`
			// Which door they came through: an invite the owner shared (with
			// its live label), or a cold request. The display name is the
			// caller's own claim; the invite is the owner's own context, and
			// it is the more trustworthy of the two.
			ViaInvite   bool   `json:"via_invite"`
			InviteLabel string `json:"invite_label,omitempty"`
		}
		var labels map[string]string
		pending := []row{}
		for _, c := range list {
			if c.Status != "pending_in" {
				continue
			}
			rw := row{Fingerprint: c.Fingerprint, DisplayName: c.DisplayName, ViaInvite: c.InviteID != ""}
			if c.InviteID != "" {
				if labels == nil {
					labels = map[string]string{}
					if invs, err := d.Store.ListInvites(r.Context(), account); err == nil {
						for _, inv := range invs {
							labels[inv.ID] = inv.Label
						}
					}
				}
				rw.InviteLabel = labels[c.InviteID]
			}
			pending = append(pending, rw)
		}
		apiJSON(w, map[string]any{"pending": pending, "presets": presetNames(r.Context(), d.Store)})
	})

	mux.HandleFunc("POST /requests/{fpr}/approve", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		fpr := r.PathValue("fpr")
		_ = r.ParseForm()
		c, err := d.Store.GetContact(r.Context(), account, fpr)
		if err != nil || c.Status != "pending_in" {
			d.Audit("contact_approve", withAccount(r, "contact:"+fpr), "error")
			http.NotFound(w, r)
			return
		}
		if err := d.Store.UpdateContactStatus(r.Context(), account, fpr, "active"); err != nil {
			d.Audit("contact_approve", withAccount(r, "contact:"+fpr), "error")
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		bundles := contacts.LoadPresets(r.Context(), d.Store)
		if preset := r.Form.Get("preset"); preset != "" {
			if perms, ok := bundles[preset]; ok {
				_ = d.Store.UpdateContactPermissions(r.Context(), account, fpr, perms, preset)
			}
		}
		if d.Invalidate != nil {
			_ = d.Invalidate(r.Context(), account, fpr)
		}
		// Tell them. The approval is already recorded, so a peer that cannot be
		// reached this second does not undo it — but the owner is told, because
		// otherwise the contact silently stays pending_out on their side.
		notice := ""
		if d.Approved != nil {
			var granted []string
			if preset := r.Form.Get("preset"); preset != "" {
				granted = bundles[preset]
			}
			if err := d.Approved(r.Context(), account, fpr, granted); err != nil {
				notice = "Approved. They could not be told yet (" + err.Error() +
					"), so they still see this as pending until they are reachable."
			}
		}
		_ = notice
		d.Audit("contact_approve", withAccount(r, "contact:"+fpr), "ok")
		http.Redirect(w, r, "/requests?account="+account, http.StatusSeeOther)
	})

	mux.HandleFunc("POST /requests/{fpr}/reject", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		fpr := r.PathValue("fpr")
		c, err := d.Store.GetContact(r.Context(), account, fpr)
		if err != nil || c.Status != "pending_in" {
			d.Audit("contact_reject", withAccount(r, "contact:"+fpr), "error")
			http.NotFound(w, r)
			return
		}
		// silent demotion: a rejected requester is indistinguishable from a stranger
		if err := d.Store.UpdateContactStatus(r.Context(), account, fpr, "blocked"); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		if d.Invalidate != nil {
			_ = d.Invalidate(r.Context(), account, fpr)
		}
		d.Audit("contact_reject", withAccount(r, "contact:"+fpr), "ok")
		http.Redirect(w, r, "/requests?account="+account, http.StatusSeeOther)
	})

	mux.HandleFunc("GET /api/invites", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		list, err := d.Store.ListInvites(r.Context(), account)
		if err != nil {
			http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
			return
		}
		apiJSON(w, map[string]any{
			"invites": list, "presets": presetNames(r.Context(), d.Store), "public_url": d.publicURL(),
		})
	})

	mux.HandleFunc("POST /invites/create", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		_ = r.ParseForm()
		var maxUses int64 = 1
		fmt.Sscanf(r.Form.Get("max_uses"), "%d", &maxUses)
		token, _, err := d.Contacts.CreateInvite(r.Context(), account, contacts.InviteOptions{
			Label: r.Form.Get("label"), MaxUses: maxUses,
			AutoAccept: r.Form.Get("auto_accept") == "1", Preset: r.Form.Get("preset"),
		})
		if err != nil {
			d.Audit("invite_create", "account:"+account, "error")
			http.Error(w, "create failed", http.StatusBadRequest)
			return
		}
		d.Audit("invite_create", "account:"+account, "ok")
		// token appears exactly once, carried in the redirect
		http.Redirect(w, r, "/invites?account="+account+"&new="+token, http.StatusSeeOther)
	})

	mux.HandleFunc("POST /invites/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		id := r.PathValue("id")
		if err := d.Store.RevokeInvite(r.Context(), id, nowUnix()); err != nil {
			d.Audit("invite_revoke", withAccount(r, "invite:"+id), "error")
			http.NotFound(w, r)
			return
		}
		d.Audit("invite_revoke", withAccount(r, "invite:"+id), "ok")
		http.Redirect(w, r, "/invites?account="+account, http.StatusSeeOther)
	})

	mux.HandleFunc("GET /api/card", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		card, a, err := d.buildCard(r, account)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		sig := ""
		if d.SignCard != nil {
			sig, _ = d.SignCard(account, card)
		}
		apiJSON(w, map[string]any{"card": card, "sig": sig, "slug": a.Slug})
	})

	mux.HandleFunc("GET /card.vcf", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
		card, a, err := d.buildCard(r, account)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+a.Slug+`.vcf"`)
		_, _ = w.Write([]byte(card))
	})
}

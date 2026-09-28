package internalui

// Management pages (SPEC §8.2): contact-request approvals, invite lifecycle, and
// the card builder with .vcf export. Every mutation audits.

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

type ManageDeps struct {
	Store    store.Store
	Contacts *contacts.Manager
	Audit    func(action, resource, outcome string)
	// Invalidate drops a caller's composed tool surface, so their next request is composed anew. Approving a
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
	// Rejected tells the peer their request was declined (`contact_rejected`), for the same
	// reason: a requester nobody tells waits at pending_out for ever. Nil skips the call.
	Rejected func(ctx context.Context, accountID, contactFpr string) error
}

// owner is the lifecycle both surfaces call (contacts.Owner), with this surface's hooks.
func (d ManageDeps) owner() contacts.Owner {
	return contacts.Owner{Manager: d.Contacts, Invalidate: d.Invalidate, TellApproved: d.Approved, TellRejected: d.Rejected}
}

// lifecycleStatus is the HTTP answer to a refused lifecycle action.
func lifecycleStatus(err error) int {
	switch {
	case errors.Is(err, contacts.ErrUnknownContact):
		return http.StatusNotFound
	case errors.Is(err, contacts.ErrWrongState):
		return http.StatusConflict
	case errors.Is(err, contacts.ErrBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, contacts.ErrContactCap):
		return http.StatusPaymentRequired
	}
	return http.StatusInternalServerError
}

// redirectRequests returns to the Requests tab, with a notice when there is one to show.
func redirectRequests(w http.ResponseWriter, r *http.Request, account, notice string) {
	q := url.Values{}
	q.Set("account", account)
	if notice != "" {
		q.Set("notice", notice)
	}
	http.Redirect(w, r, "/requests?"+q.Encode(), http.StatusSeeOther)
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
	// There is no card without a leaf: the certificate IS the card (PACT §3), so an
	// account whose wallet has not issued one yet has nothing to serve rather than a
	// key to spell out. This used to fall back to a 1.x card built from the bare
	// fingerprint, which is exactly the shape that no longer exists.
	return "", a, fmt.Errorf("this account has no certificate yet; its card exists once a wallet has issued a leaf")
}

// decideAddress is the handler for one answer to a contact waiting at a new address.
//
// The owner's answer to a contact waiting at a new address: the decision the owner MCP's
// approve_address / reject_address and the CLI's `account address` make, audited alike. Each
// route is a literal: the parity tests read the routes from the source.
func (d ManageDeps) decideAddress(approve bool) http.HandlerFunc {
	decision := "reject"
	if approve {
		decision = "approve"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		account := accountParam(r)
		root := r.PathValue("root")
		p, err := d.owner().DecideAddress(r.Context(), account, root, approve)
		if err != nil {
			d.Audit("contact_address_"+decision, withAccount(r, "contact:"+root), "error")
			http.Error(w, err.Error(), lifecycleStatus(err))
			return
		}
		d.Audit("contact_address_"+decision, withAccount(r, "contact:"+root+" endpoint:"+p.Endpoint), "ok")
		redirectRequests(w, r, account, "")
	}
}

func MountManagePages(mux *http.ServeMux, d ManageDeps) {
	mux.HandleFunc("GET /api/requests", d.getAPIRequests)
	mux.HandleFunc("POST /requests/addresses/{root}/approve", d.decideAddress(true))
	mux.HandleFunc("POST /requests/addresses/{root}/reject", d.decideAddress(false))
	mux.HandleFunc("POST /requests/{fpr}/approve", d.postRequestsFprApprove)
	mux.HandleFunc("POST /requests/{fpr}/reject", d.postRequestsFprReject)
	mux.HandleFunc("GET /api/invites", d.getAPIInvites)
	mux.HandleFunc("POST /invites/create", d.postInvitesCreate)
	mux.HandleFunc("POST /invites/{id}/revoke", d.postInvitesIDRevoke)
	mux.HandleFunc("GET /api/card", d.getAPICard)
	mux.HandleFunc("GET /card.vcf", d.getCardVCF)
}

// addressClaim is a request's claim on another contact's address, {root, name}.
type addressClaim struct {
	Root string `json:"root"`
	Name string `json:"name"`
}

// getAPIRequests serves `GET /api/requests`.
func (d ManageDeps) getAPIRequests(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
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
		// AddressClaim is the contact whose address this request comes from, now or within the
		// claim window: PACT §5.2, "shown to the owner beside the name of the contact who holds or
		// held that address". The owner MCP's list_contacts and the cloud answer the same shape.
		AddressClaim *addressClaim `json:"address_claim,omitempty"`
	}
	var labels map[string]string
	pending := []row{}
	for _, c := range list {
		if c.Status != "pending_in" {
			continue
		}
		rw := row{Fingerprint: c.Fingerprint, DisplayName: c.DisplayName, ViaInvite: c.InviteID != ""}
		if d.Contacts != nil {
			if claim, err := d.Contacts.AddressClaim(r.Context(), account, c.Endpoint, c.Fingerprint); err == nil && claim != "" {
				ac := &addressClaim{Root: claim, Name: claim}
				for _, held := range list {
					if held.Fingerprint == claim {
						ac.Name = cmp.Or(held.Petname, held.DisplayName, claim)
					}
				}
				rw.AddressClaim = ac
			}
		}
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
	// Contacts waiting at a new address appear beside the requests (PACT §5.3 under `ask`).
	addresses, err := d.owner().PendingAddresses(r.Context(), account)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	apiJSON(w, map[string]any{"pending": pending, "addresses": addresses, "presets": presetNames(r.Context(), d.Store)})
}

// postRequestsFprApprove serves `POST /requests/{fpr}/approve`.
func (d ManageDeps) postRequestsFprApprove(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fpr := r.PathValue("fpr")
	_ = r.ParseForm()
	dec, err := d.owner().Approve(r.Context(), account, fpr, r.Form.Get("preset"))
	if err != nil {
		d.Audit("contact_approve", withAccount(r, "contact:"+fpr), "error")
		http.Error(w, err.Error(), lifecycleStatus(err))
		return
	}
	d.Audit("contact_approve", withAccount(r, "contact:"+fpr), "ok")
	// The approval is recorded whether or not they heard it; when they did not, the owner
	// is told, because otherwise the contact silently stays pending_out on their side.
	notice := ""
	if !dec.Told {
		notice = "Approved. They could not be told yet (" + dec.Why +
			"), so they still see this as pending until they are reachable."
	}
	redirectRequests(w, r, account, notice)
}

// postRequestsFprReject serves `POST /requests/{fpr}/reject`.
func (d ManageDeps) postRequestsFprReject(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fpr := r.PathValue("fpr")
	// A demotion to blocked, not a deletion (PACT §5.1): their next request is answered as a
	// stranger's and never reaches the owner. They are told, so they do not wait for ever.
	dec, err := d.owner().Reject(r.Context(), account, fpr)
	if err != nil {
		d.Audit("contact_reject", withAccount(r, "contact:"+fpr), "error")
		http.Error(w, err.Error(), lifecycleStatus(err))
		return
	}
	d.Audit("contact_reject", withAccount(r, "contact:"+fpr), "ok")
	notice := ""
	if !dec.Told && dec.Why != "" {
		notice = "Rejected. They could not be told (" + dec.Why +
			"), so their side still shows the request as waiting."
	}
	redirectRequests(w, r, account, notice)
}

// getAPIInvites serves `GET /api/invites`.
func (d ManageDeps) getAPIInvites(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	list, err := d.Store.ListInvites(r.Context(), account)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	apiJSON(w, map[string]any{
		"invites": list, "presets": presetNames(r.Context(), d.Store), "public_url": d.publicURL(),
	})
}

// postInvitesCreate serves `POST /invites/create`.
func (d ManageDeps) postInvitesCreate(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
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
}

// postInvitesIDRevoke serves `POST /invites/{id}/revoke`.
func (d ManageDeps) postInvitesIDRevoke(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	id := r.PathValue("id")
	if err := d.Store.RevokeInvite(r.Context(), account, id, nowUnix()); err != nil {
		d.Audit("invite_revoke", withAccount(r, "invite:"+id), "error")
		// The owner MCP's revoke_invite makes the same distinction: only a missing or spent
		// invite is a 404; a store that failed is a 500.
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "could not revoke the invite", http.StatusInternalServerError)
		}
		return
	}
	d.Audit("invite_revoke", withAccount(r, "invite:"+id), "ok")
	http.Redirect(w, r, "/invites?account="+account, http.StatusSeeOther)
}

// getAPICard serves `GET /api/card`.
func (d ManageDeps) getAPICard(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
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
}

// getCardVCF serves `GET /card.vcf`.
func (d ManageDeps) getCardVCF(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	card, a, err := d.buildCard(r, account)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+a.Slug+`.vcf"`)
	_, _ = w.Write([]byte(card))
}

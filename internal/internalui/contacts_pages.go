package internalui

// Contact pages (SPEC §8.2): list, and the per-contact switchboard — permission
// toggles, preset apply, and the message-vs-instruction trust flag. Every mutation
// persists, audits, and invalidates the caller's composed server so the caller's next
// request is composed from the new grant (SPEC §2.4).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Invalidator drops a caller's composed server (public.Pool.Invalidate).
type Invalidator func(ctx context.Context, accountID, fpr string) error

// ContactsDeps is what the contact routes need: the list, the per-contact switchboard, the
// lifecycle (remove, block, unblock), and the calls to a contact's server.
type ContactsDeps struct {
	Store store.Store
	// Invalidate drops the caller's composed server after a grant changes. The permissions route
	// calls it without a nil check.
	Invalidate Invalidator
	// ListTools and Call reach a contact's server as this account — what they
	// let us call there, and calling it. Both go through the node's outbound
	// path (sealed or plain as the peer's card says), the same path the owner
	// MCP's call_contact uses, so the two surfaces cannot disagree.
	ListTools func(ctx context.Context, accountID, fpr string) ([]ContactTool, error)
	Call      func(ctx context.Context, accountID, fpr, tool string, args map[string]any) (string, error)
	// Audit records the page's mutations and contact calls. The permissions, petname and trust
	// handlers call it without a nil check.
	Audit func(action, resource, outcome string)
	// AddContact is the owner reaching out with THIS account's identity — the
	// owner-initiated half of contact establishment (SPEC §9): redeem the invite
	// link they were sent, or, with no link, ask the holder of a card they have out
	// of band (§9.3's import; the HDTP §5.2 manual flow, landing pending_out). It is
	// the same function the owner MCP's add_contact calls: the portal and the agent
	// surface are meant to be at parity (§8.4), and a second implementation here
	// would be a second set of bugs. Nil hides both forms rather than offering a
	// button that cannot work. status is the row's: active or pending_out.
	AddContact func(ctx context.Context, accountID, inviteURL, card, note, grant string) (fingerprint, status string, err error)
	// RefreshContact re-fetches ONE contact's signed card because the owner pressed the
	// button on that contact's page: a renewed certificate, a changed name or seal policy.
	// The same function as the owner MCP's refresh_contact (§8.4 parity). There is no
	// route that refreshes more than the contact in its path. Nil answers 404.
	RefreshContact func(ctx context.Context, accountID, fpr string) (outcome, why string, err error)
	// ServedPermissions names every contact-tier permission this account's
	// public surface currently gates a tool with, beyond the core five. It is
	// how a live integration's permission reaches the switchboard; nil offers
	// only the core rows.
	ServedPermissions func(accountID string) []string
	// ContactCap is how many contacts each account may hold (limit.contacts), which an unblock
	// that restores a contact is held to. Nil is the default.
	ContactCap func() int
}

// offered is this contact's switchboard (contacts.Offered): the core permissions, whatever this
// account's surface currently gates a tool with, and anything the contact already holds.
//
// It is the allow-list on save for the same reason it is the row list on
// render. When the two disagreed, the portal offered a switch and the save threw
// the answer away: an exposed integration could be granted, answered 200, was
// audited ok, and persisted nothing, so the tool never reached the contact.
func (d ContactsDeps) offered(accountID string, held []string) []string {
	var served []string
	if d.ServedPermissions != nil {
		served = d.ServedPermissions(accountID)
	}
	return contacts.Offered(served, held)
}

// owner is the lifecycle both surfaces call (contacts.Owner). Telling a removed contact is
// the node's one outbound path — the same Call the owner MCP's remove_contact reaches.
func (d ContactsDeps) owner() contacts.Owner {
	o := contacts.Owner{Manager: &contacts.Manager{Store: d.Store, ContactCap: d.ContactCap}, Invalidate: d.Invalidate}
	if d.Call != nil {
		o.TellRemoved = func(ctx context.Context, accountID, fpr string) error {
			_, err := d.Call(ctx, accountID, fpr, core.ToolRemoveContact, map[string]any{})
			return err
		}
	}
	return o
}

// redirectContacts returns to the list with a message. A redirect rather than a
// rendered response so a refresh does not re-submit the invite.
func redirectContacts(w http.ResponseWriter, r *http.Request, account, notice, errMsg string) {
	q := url.Values{}
	if account != "" {
		q.Set("account", account)
	}
	if notice != "" {
		q.Set("added", notice)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	http.Redirect(w, r, "/contacts?"+q.Encode(), http.StatusSeeOther)
}

// ContactTool is one entry of a contact's tools/list for this identity, as the peer answered it.
type ContactTool struct {
	// Name is the tool's name on the contact's server, what POST /contacts/{fpr}/call takes as `tool`.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// InputSchema is the peer's JSON Schema for the tool's arguments, passed through untouched.
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// MountContactPages registers the contact routes on mux.
func MountContactPages(mux *http.ServeMux, d ContactsDeps) {
	mux.HandleFunc("GET /api/contacts/{fpr}/tools", d.getAPIContactsFprTools)
	mux.HandleFunc("POST /contacts/{fpr}/call", d.postContactsFprCall)
	mux.HandleFunc("GET /api/contacts", d.getAPIContacts)
	mux.HandleFunc("POST /contacts/{fpr}/remove", d.postContactsFprRemove)
	mux.HandleFunc("POST /contacts/{fpr}/block", d.postContactsFprBlock)
	mux.HandleFunc("POST /contacts/{fpr}/unblock", d.postContactsFprUnblock)

	// Accepting an invite somebody sent you: the owner-initiated half of contact
	// establishment (SPEC §9), which until now existed only on the owner MCP.
	if d.AddContact != nil {
		mux.HandleFunc("POST /contacts/add", d.postContactsAdd)
	}

	mux.HandleFunc("GET /api/contacts/{fpr}", d.getAPIContactsFpr)
	mux.HandleFunc("POST /contacts/{fpr}/permissions", d.postContactsFprPermissions)
	mux.HandleFunc("POST /contacts/{fpr}/petname", d.postContactsFprPetname)
	mux.HandleFunc("POST /contacts/{fpr}/refresh", d.postContactsFprRefresh)
	mux.HandleFunc("POST /contacts/{fpr}/trust", d.postContactsFprTrust)
}

// getAPIContactsFprTools serves `GET /api/contacts/{fpr}/tools`.
//
// What the contact lets this identity call on their server. The list is
// the peer's answer, already filtered by their switchboard; this node adds
// nothing and hides nothing.
func (d ContactsDeps) getAPIContactsFprTools(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fpr := r.PathValue("fpr")
	if d.ListTools == nil {
		apiJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"error": "this node cannot call contacts yet"})
		return
	}
	tools, err := d.ListTools(r.Context(), account, fpr)
	if err != nil {
		apiJSONStatus(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if tools == nil {
		tools = []ContactTool{}
	}
	apiJSON(w, map[string]any{"tools": tools})
}

// postContactsFprCall serves `POST /contacts/{fpr}/call`.
//
// One call to a contact's server on the owner's behalf. Arguments arrive as a
// JSON object in the `args` field — a form cannot carry nested values — and
// are passed through untouched: the peer's own schema and switchboard judge
// them. The answer is the raw tool result, so the page can show exactly what
// the contact said.
func (d ContactsDeps) postContactsFprCall(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := formOrQuery(r, "account")
	fpr := r.PathValue("fpr")
	tool := strings.TrimSpace(r.PostForm.Get("tool"))
	if tool == "" || d.Call == nil {
		apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "which tool?"})
		return
	}
	args := map[string]any{}
	if raw := strings.TrimSpace(r.PostForm.Get("args")); raw != "" {
		if len(raw) > 64<<10 {
			apiJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "arguments over 64 KiB"})
			return
		}
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			apiJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "arguments must be a JSON object"})
			return
		}
	}
	out, err := d.Call(r.Context(), account, fpr, tool, args)
	if err != nil {
		if d.Audit != nil {
			d.Audit("call_contact", withAccount(r, "contact:"+fpr+" tool:"+tool), "failed")
		}
		apiJSONStatus(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if d.Audit != nil {
		d.Audit("call_contact", withAccount(r, "contact:"+fpr+" tool:"+tool), "ok")
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"result":` + out + `}`))
}

// getAPIContacts serves `GET /api/contacts`.
func (d ContactsDeps) getAPIContacts(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	list, err := d.Store.ListContacts(r.Context(), account)
	if err != nil {
		http.Error(w, `{"error":"store"}`, http.StatusInternalServerError)
		return
	}
	// Labels, never raw names: the name each contact carries is the name IT
	// chose, and two of them may match (labelContacts decorates collisions).
	labels := labelContacts(list)
	type row struct {
		Fingerprint string `json:"fingerprint"`
		Label       string `json:"label"`
		Status      string `json:"status"`
	}
	rows := make([]row, 0, len(list))
	for _, c := range list {
		rows = append(rows, row{Fingerprint: c.Fingerprint, Label: labels[c.Fingerprint], Status: c.Status})
	}
	apiJSON(w, map[string]any{
		"contacts": rows, "presets": presetNames(r.Context(), d.Store), "can_add": d.AddContact != nil,
	})
}

// postContactsFprRemove serves `POST /contacts/{fpr}/remove`.
//
// Ending one, in any state: an active contact is told (HDTP §5: removal notifies the peer
// and is effective locally regardless, bounded so an unreachable peer never blocks the
// owner's decision); a waiting request, our own approach or a blocked root goes silently.
func (d ContactsDeps) postContactsFprRemove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := formOrQuery(r, "account")
	fpr := r.PathValue("fpr")
	prior, _ := d.Store.GetContact(r.Context(), account, fpr)
	dec, err := d.owner().Remove(r.Context(), account, fpr)
	if err != nil {
		d.audit("contact_remove", withAccount(r, "contact:"+fpr), "error")
		redirectContacts(w, r, account, "", "could not remove them: "+err.Error())
		return
	}
	d.audit("contact_remove", withAccount(r, "contact:"+fpr), "ok")
	notice := "Removed."
	if prior.Status == "active" && !dec.Told {
		notice = "Removed. They could not be told, so their node may still list you."
	}
	redirectContacts(w, r, account, notice, "")
}

// postContactsFprBlock serves `POST /contacts/{fpr}/block`.
//
// Blocking is silent (SPEC §9.1, HDTP §5.2): they are served as a stranger and told nothing.
func (d ContactsDeps) postContactsFprBlock(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := formOrQuery(r, "account")
	fpr := r.PathValue("fpr")
	if _, err := d.owner().Block(r.Context(), account, fpr); err != nil {
		d.audit("contact_block", withAccount(r, "contact:"+fpr), "error")
		redirectContacts(w, r, account, "", "could not block them: "+err.Error())
		return
	}
	d.audit("contact_block", withAccount(r, "contact:"+fpr), "ok")
	redirectContacts(w, r, account, "Blocked. They are not told; they now see what a stranger sees.", "")
}

// postContactsFprUnblock serves `POST /contacts/{fpr}/unblock`.
//
// The way out of blocked, silent as the block was. A contact that was ever active comes
// back as it was; a request that was rejected is forgotten, and they may ask again.
func (d ContactsDeps) postContactsFprUnblock(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := formOrQuery(r, "account")
	fpr := r.PathValue("fpr")
	dec, err := d.owner().Unblock(r.Context(), account, fpr)
	if err != nil {
		d.audit("contact_unblock", withAccount(r, "contact:"+fpr), "error")
		redirectContacts(w, r, account, "", "could not unblock them: "+err.Error())
		return
	}
	d.audit("contact_unblock", withAccount(r, "contact:"+fpr+" status:"+dec.Status), "ok")
	notice := "Unblocked. They are a contact again, with the permissions they had."
	if dec.Status == "none" {
		notice = "Unblocked. They were never a contact, so they are forgotten: they may ask again."
	}
	redirectContacts(w, r, account, notice, "")
}

// postContactsAdd serves `POST /contacts/add`.
func (d ContactsDeps) postContactsAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := accountParam(r)
	if account == "" {
		account = r.PostForm.Get("account")
	}
	inviteURL := strings.TrimSpace(r.PostForm.Get("invite_url"))
	card := strings.TrimSpace(r.PostForm.Get("card"))
	if inviteURL == "" && card == "" {
		redirectContacts(w, r, account, "", "paste the invite link they sent you, or their card")
		return
	}
	fpr, status, err := d.AddContact(r.Context(), account, inviteURL, card,
		strings.TrimSpace(r.PostForm.Get("note")), r.PostForm.Get("grant"))
	if err != nil {
		if d.Audit != nil {
			// the URL is a bearer credential; the KEY of the failure is
			// audited, never the link itself
			d.Audit("contact_add", "account:"+account, "refused")
		}
		redirectContacts(w, r, account, "", err.Error())
		return
	}
	if d.Audit != nil {
		d.Audit("contact_add", withAccount(r, "peer:"+fpr), "ok")
	}
	notice := "Added " + fpr
	if status == "pending_out" {
		notice = "Asked " + fpr + " to connect. They are listed as waiting until their owner approves."
	}
	redirectContacts(w, r, account, notice, "")
}

// getAPIContactsFpr serves `GET /api/contacts/{fpr}`.
func (d ContactsDeps) getAPIContactsFpr(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	c, err := d.Store.GetContact(r.Context(), account, r.PathValue("fpr"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	granted := map[string]bool{}
	for _, p := range c.Permissions {
		granted[p] = true
	}
	type row struct {
		Name string `json:"name"`
		On   bool   `json:"on"`
	}
	names := d.offered(account, c.Permissions)
	rows := make([]row, 0, len(names))
	for _, p := range names {
		rows = append(rows, row{Name: p, On: granted[p]})
	}
	apiJSON(w, map[string]any{
		"fingerprint":  c.Fingerprint,
		"display_name": c.DisplayName,
		"petname":      c.Petname,
		"status":       c.Status,
		// whether an unblock restores them (true) or forgets a rejected request (false)
		"was_contact":       c.EverActive,
		"preset":            heldPreset(contacts.LoadPresets(r.Context(), d.Store), c),
		"trust":             c.TrustFlag,
		"permissions":       rows,
		"their_permissions": c.TheirPermissions,
		"presets":           presetNames(r.Context(), d.Store),
	})
}

// postContactsFprPermissions serves `POST /contacts/{fpr}/permissions`.
func (d ContactsDeps) postContactsFprPermissions(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fpr := r.PathValue("fpr")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	submitted := r.Form.Get("preset")
	apply := r.Form.Get("apply_preset") == "1"
	var held []string
	var preset string
	if c, err := d.Store.GetContact(r.Context(), account, fpr); err == nil {
		held, preset = c.Permissions, c.Preset
	}
	bundles := contacts.LoadPresets(r.Context(), d.Store)
	var perms []string
	if applied, ok := bundles[submitted]; ok && apply {
		// A preset sets the documented core bundle wholesale. It says nothing
		// about an integration this contact was deliberately granted (SPEC
		// section 6.4) — those are not in any bundle and never could be, so
		// applying one would silently revoke a capability the owner chose,
		// from a control that never mentions it.
		perms = append(perms, applied...)
		preset = submitted
		core := map[string]bool{}
		for _, p := range contacts.AllPermissions {
			core[p] = true
		}
		for _, p := range held {
			if !core[p] {
				perms = append(perms, p)
			}
		}
	} else {
		offered := d.offered(account, held)
		for _, p := range r.Form["perm"] {
			// only what the switchboard offered persists: no free-form grants,
			// and nothing this surface cannot serve
			for _, known := range offered {
				if p == known {
					perms = append(perms, p)
				}
			}
		}
	}
	// Applying "custom" is a decision about the preset exactly as applying
	// a bundle is: the owner said this grant wears no name, and that holds
	// even when the switches happen to still equal the old bundle.
	if apply && submitted == "" {
		preset = ""
	}
	// The label has to survive the save on its own merits. A hand-edited
	// switchboard is a bespoke grant, and a bespoke grant wears no preset —
	// keeping the old name here is how a record ends up claiming "family"
	// over permissions nobody chose as family.
	if !bundles.Holds(preset, perms) {
		preset = ""
	}
	if err := d.Store.UpdateContactPermissions(r.Context(), account, fpr, perms, preset); err != nil {
		d.Audit("permissions_update", withAccount(r, "contact:"+fpr), "error")
		http.NotFound(w, r)
		return
	}
	// What the grant became, and whether a preset did it: an outcome of "ok"
	// with no record of the resulting set cannot answer "who removed this",
	// which is the question a switchboard change actually raises.
	label := "custom"
	if preset != "" {
		label = preset
	}
	d.Audit("permissions_update",
		withAccount(r, "contact:"+fpr+" perms:"+strings.Join(perms, ",")+" preset:"+label), "ok")
	_ = d.Invalidate(r.Context(), account, fpr)
	http.Redirect(w, r, "/contacts/"+fpr+"?account="+account, http.StatusSeeOther)
}

// postContactsFprPetname serves `POST /contacts/{fpr}/petname`.
//
// The owner's own name for a contact. Local by construction: it is never
// sent anywhere, and no peer surface can reach it — which is the whole point,
// since display_name is the contact's own claim and several people honestly
// share a name.
func (d ContactsDeps) postContactsFprPetname(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fpr := r.PathValue("fpr")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	petname := strings.TrimSpace(r.Form.Get("petname"))
	if len([]rune(petname)) > contacts.MaxDisplayName {
		http.Error(w, "name too long", http.StatusBadRequest)
		return
	}
	if err := d.Store.SetContactPetname(r.Context(), account, fpr, petname); err != nil {
		d.Audit("contact_petname", withAccount(r, "contact:"+fpr), "error")
		http.NotFound(w, r)
		return
	}
	d.Audit("contact_petname", withAccount(r, "contact:"+fpr), "ok")
	http.Redirect(w, r, "/contacts/"+fpr+"?account="+account, http.StatusSeeOther)
}

// postContactsFprRefresh serves `POST /contacts/{fpr}/refresh`.
//
// Refresh THIS contact. JSON rather than a redirect, because what the owner wants is
// the outcome — unchanged, updated, renewed, unreachable, refused and why — and a
// redirect would throw it away. The audit rows are the node's own (`contact_refresh`,
// `contact_renewal`), written where the decision is made.
func (d ContactsDeps) postContactsFprRefresh(w http.ResponseWriter, r *http.Request) {
	if d.RefreshContact == nil {
		http.NotFound(w, r)
		return
	}
	outcome, why, err := d.RefreshContact(r.Context(), accountParam(r), r.PathValue("fpr"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	apiJSON(w, map[string]string{"outcome": outcome, "why": why})
}

// postContactsFprTrust serves `POST /contacts/{fpr}/trust`.
func (d ContactsDeps) postContactsFprTrust(w http.ResponseWriter, r *http.Request) {
	account := accountParam(r)
	fpr := r.PathValue("fpr")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	trust := r.Form.Get("trust")
	if trust != "messages_only" && trust != "may_instruct" {
		http.Error(w, "bad trust flag", http.StatusBadRequest)
		return
	}
	if err := d.Store.UpdateContactTrust(r.Context(), account, fpr, trust); err != nil {
		d.Audit("trust_update", withAccount(r, "contact:"+fpr+" trust:"+trust), "error")
		http.NotFound(w, r)
		return
	}
	d.Audit("trust_update", withAccount(r, "contact:"+fpr+" trust:"+trust), "ok")
	http.Redirect(w, r, "/contacts/"+fpr+"?account="+account, http.StatusSeeOther)
}

func apiJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// heldPreset is the preset name a contact has actually earned. The record keeps
// what the owner chose, but a label is only shown while the grant still is that
// bundle — a stored name that no longer describes the switchboard is a lie the
// portal would otherwise repeat on every screen, including chat.
func heldPreset(bundles contacts.PresetSet, c store.Contact) string {
	if bundles.Holds(c.Preset, c.Permissions) {
		return c.Preset
	}
	return ""
}

func (d ContactsDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

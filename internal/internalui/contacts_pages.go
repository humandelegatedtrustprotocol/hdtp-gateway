package internalui

// Contact pages (SPEC §8.2): list, and the per-contact switchboard — permission
// toggles, preset apply, and the message-vs-instruction trust flag. Every mutation
// persists, audits, and invalidates the caller's composed server so a live session
// hears tools/list_changed (SPEC §2.4).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// Invalidator drops + reconciles a caller's composed server (public.Pool.Invalidate).
type Invalidator func(ctx context.Context, accountID, fpr string) error

type ContactsDeps struct {
	Store      store.Store
	Invalidate Invalidator
	// ListTools and Call reach a contact's server as this account — what they
	// let us call there, and calling it. Both go through the node's outbound
	// path (sealed or plain as the peer's card says), the same path the owner
	// MCP's call_contact uses, so the two surfaces cannot disagree.
	ListTools func(ctx context.Context, accountID, fpr string) ([]ContactTool, error)
	Call      func(ctx context.Context, accountID, fpr, tool string, args map[string]any) (string, error)
	Audit     func(action, resource, outcome string)
	// AddContact redeems somebody's invite link with THIS account's identity —
	// the owner-initiated half of contact establishment (SPEC §9). It is the same
	// function the owner MCP's add_contact calls: the portal and the agent surface
	// are meant to be at parity (§8.4), and a second implementation here would be
	// a second set of bugs. Nil hides the form rather than offering a button that
	// cannot work.
	AddContact func(ctx context.Context, accountID, inviteURL, grant string) (fingerprint string, err error)
	// ServedPermissions names every contact-tier permission this account's
	// public surface currently gates a tool with, beyond the core five. It is
	// how a live integration's permission reaches the switchboard; nil offers
	// only the core rows.
	ServedPermissions func(accountID string) []string
}

// offered is this contact's switchboard: the core permissions, whatever this
// account's surface currently gates a tool with (an integration's
// integration.<slug>, SPEC section 6.4), and anything the contact already holds
// so a save cannot drop a grant the owner never touched.
//
// It is the allow-list on save for the same reason it is the row list on
// render. When the two disagreed, the portal offered a switch and the save threw
// the answer away: an exposed integration could be granted, answered 200, was
// audited ok, and persisted nothing, so the tool never reached the contact.
func (d ContactsDeps) offered(accountID string, held []string) []string {
	out := append([]string{}, contacts.AllPermissions...)
	seen := map[string]bool{}
	for _, p := range out {
		seen[p] = true
	}
	add := func(ps []string) {
		for _, p := range ps {
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if d.ServedPermissions != nil {
		add(d.ServedPermissions(accountID))
	}
	add(held)
	return out
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

// MountContactPages registers the contact routes on mux.
// ContactTool is one entry of a contact's tools/list for this identity.
type ContactTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

func MountContactPages(mux *http.ServeMux, d ContactsDeps) {
	// What the contact lets this identity call on their server. The list is
	// the peer's answer, already filtered by their switchboard; this node adds
	// nothing and hides nothing.
	mux.HandleFunc("GET /api/contacts/{fpr}/tools", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
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
	})

	// One call to a contact's server on the owner's behalf. Arguments arrive as a
	// JSON object in the `args` field — a form cannot carry nested values — and
	// are passed through untouched: the peer's own schema and switchboard judge
	// them. The answer is the raw tool result, so the page can show exactly what
	// the contact said.
	mux.HandleFunc("POST /contacts/{fpr}/call", func(w http.ResponseWriter, r *http.Request) {
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
	})

	mux.HandleFunc("GET /api/contacts", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
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
	})

	// Ending one. RemoveContact and DeleteContact both existed; the portal had no
	// way to reach either, so a contact could be added and never dropped.
	mux.HandleFunc("POST /contacts/{fpr}/remove", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		account := formOrQuery(r, "account")
		fpr := r.PathValue("fpr")
		// PACT §5: removal notifies the peer and is effective locally
		// regardless. Best effort, BEFORE the delete — the outbound path needs
		// the contact row's card — and bounded, so an unreachable peer never
		// blocks the owner's own decision. Only an active relationship has
		// anything to notify; the call itself is audited by CallContact.
		notified := true
		if d.Call != nil {
			if c, err := d.Store.GetContact(r.Context(), account, fpr); err == nil && c.Status == "active" {
				nctx, cancel := context.WithTimeout(r.Context(), removeNotifyBudget)
				_, callErr := d.Call(nctx, account, fpr, "remove_contact", map[string]any{})
				cancel()
				notified = callErr == nil
			}
		}
		if err := d.Store.DeleteContact(r.Context(), account, fpr); err != nil {
			if d.Audit != nil {
				d.Audit("contact_remove", withAccount(r, "contact:"+fpr), "error")
			}
			redirectContacts(w, r, account, "", "could not remove them: "+err.Error())
			return
		}
		if d.Invalidate != nil {
			// Drop their composed server at once, or a cached one keeps serving
			// the tier they just lost.
			d.Invalidate(r.Context(), account, fpr)
		}
		if d.Audit != nil {
			d.Audit("contact_remove", withAccount(r, "contact:"+fpr), "ok")
		}
		notice := "Removed."
		if !notified {
			notice = "Removed. They could not be told, so their node may still list you."
		}
		redirectContacts(w, r, account, notice, "")
	})

	// Accepting an invite somebody sent you: the owner-initiated half of contact
	// establishment (SPEC §9), which until now existed only on the owner MCP.
	if d.AddContact != nil {
		mux.HandleFunc("POST /contacts/add", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			account := r.URL.Query().Get("account")
			if account == "" {
				account = r.PostForm.Get("account")
			}
			inviteURL := strings.TrimSpace(r.PostForm.Get("invite_url"))
			if inviteURL == "" {
				redirectContacts(w, r, account, "", "paste the invite link they sent you")
				return
			}
			fpr, err := d.AddContact(r.Context(), account, inviteURL, r.PostForm.Get("grant"))
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
			redirectContacts(w, r, account, "Added "+fpr, "")
		})
	}

	mux.HandleFunc("GET /api/contacts/{fpr}", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
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
			"fingerprint":       c.Fingerprint,
			"display_name":      c.DisplayName,
			"petname":           c.Petname,
			"status":            c.Status,
			"preset":            heldPreset(contacts.LoadPresets(r.Context(), d.Store), c),
			"trust":             c.TrustFlag,
			"permissions":       rows,
			"their_permissions": c.TheirPermissions,
			"presets":           presetNames(r.Context(), d.Store),
		})
	})

	mux.HandleFunc("POST /contacts/{fpr}/permissions", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
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
	})

	// The owner's own name for a contact. Local by construction: it is never
	// sent anywhere, and no peer surface can reach it — which is the whole point,
	// since display_name is the contact's own claim and several people honestly
	// share a name.
	mux.HandleFunc("POST /contacts/{fpr}/petname", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
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
	})

	mux.HandleFunc("POST /contacts/{fpr}/trust", func(w http.ResponseWriter, r *http.Request) {
		account := r.URL.Query().Get("account")
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
	})
}

var _ = strings.TrimSpace

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

// removeNotifyBudget bounds the courtesy remove_contact call: the peer's loss
// of access is the local delete, not this notification.
const removeNotifyBudget = 5 * time.Second

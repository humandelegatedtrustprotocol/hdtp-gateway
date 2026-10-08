package internalui

// The settings page (SPEC §8.2): reachability and the security knobs
// mode. Three rules shape it, and they are why this file is more than a form:
//
//   - A control that cannot take effect is never editable. A knob the
//     environment pinned, or one the deployment mode forces, renders locked
//     WITH the reason (`core.Config.EffectiveSettings`), because a switch that
//     silently does nothing is worse than no switch.
//   - A change that needs a restart says so, next to itself. Seal applies live;
//     anything owning a socket or a goroutine does not.
//   - A secret goes in and never comes back. Adapter credentials are stored
//     keyring-sealed and rendered as "set" or "not set", never as a value.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// SettingsDeps is what the settings routes need. A nil optional callback hides its section and
// leaves its route unregistered (SaveStorage, SavePreset, Pair, Probe; see MountSettingsPages).
type SettingsDeps struct {
	// Effective is the resolved view of every owner-settable knob.
	Effective func() []core.Effective
	// Save persists one knob after validation; it is also where a live-applied
	// change (seal) is pushed into the serving node.
	Save func(ctx context.Context, key, value string) error
	// AdapterSettings lists the stored `tunnel.<adapter>.<name>` keys and
	// whether each holds a secret. Values are never returned.
	AdapterSettings func(ctx context.Context) ([]AdapterSetting, error)
	// Adapters are the registered tunnel adapter names.
	Adapters []string
	// Pending returns the values currently STORED, which for a restart-scoped
	// knob is not what the node is running. The control shows the stored value —
	// otherwise a save appears to do nothing — while the locks and the
	// derivation keep describing the running node.
	Pending func(ctx context.Context) (map[string]string, error)
	// Pair performs an ingress pairing; nil hides the section.
	Pair func(ctx context.Context, in PairInput) (PairResult, error)
	// Unpair forgets a stored pairing.
	Unpair func(ctx context.Context, adapter string) error
	// Accounts lists the identities that could pair; a selector appears only
	// when there is more than one, so a multi-account node never pairs an
	// identity the owner did not choose.
	Accounts func(ctx context.Context) ([]AccountChoice, error)
	// Paired reports which ingress adapters have a completed pairing. An adapter
	// without one cannot start, so it must not be selectable.
	Paired func(ctx context.Context) (map[string]bool, error)
	// Storage lists each account's quota and retention window; nil hides the
	// section. Retention is per account (SPEC §7.9), so this is not a node knob.
	Storage func(ctx context.Context) ([]StorageRow, error)
	// SaveStorage records one account's storage policy.
	SaveStorage func(ctx context.Context, accountID string, quotaGiB int64, retentionDays, requestExpiryDays int) error
	// Presets/SavePreset/DeletePreset edit the owner's permission bundles
	// (HDTP §8: presets are owner-editable). nil hides the section.
	Presets func(ctx context.Context) (map[string][]string, error)
	// SavePreset stores one named bundle after contacts.ValidatePreset accepts it.
	SavePreset func(ctx context.Context, name string, perms []string) error
	// DeletePreset removes one named bundle.
	DeletePreset func(ctx context.Context, name string) error
	// Probe runs the reachability check of SPEC §10.4; nil hides the control.
	Probe func(ctx context.Context) (verdict, detail string)
	// Audit records settings changes (keys and outcomes, never values). Nil records nothing.
	Audit func(action, resource, outcome string)
}

// PairInput is what the owner types to pair with an ingress (SPEC §10.6).
type PairInput struct {
	// PairURL and Token are the pairing URL and the one-time token the owner was given. The route
	// refuses a pairing without either (and without a Subdomain).
	PairURL string
	Token   string
	// Subdomain is the name they want under the ingress's domain.
	Subdomain string
	// Mode is `passthrough` (the ingress forwards raw TLS; end-to-end mTLS) or
	// `terminate` (the ingress holds a public certificate and re-originates).
	Mode string
	// IngressFingerprint is the key the owner was given out of band. Empty is
	// trust-on-first-use, and the fingerprint actually seen is reported back.
	IngressFingerprint string
	// Account is the identity whose certificate authenticates the pairing and
	// whose fingerprint the ingress records. Empty means "the only one".
	Account string
}

// AccountChoice names one identity for the pairing selector.
type AccountChoice struct {
	// ID is the account id; Label is the text the selector shows for it.
	ID    string `json:"id"`
	Label string `json:"label"`
}

// PairResult is what a completed pairing tells the owner.
type PairResult struct {
	// PublicName and Adapter are what the success notice reports ("Paired as <PublicName> over
	// <Adapter>"). Fingerprint is the ingress key that was presented: the page prints it when the
	// owner supplied none to check against, and appends it to a refusal when they did.
	PublicName  string
	Fingerprint string
	Adapter     string
}

// Bounds on the storage form. They exist because the arithmetic downstream
// overflows: a very large day count wraps, and some values wrap to a small
// POSITIVE window that would delete almost everything.
const (
	MaxQuotaGiB          = 1 << 20 // 1 PiB
	MaxRetentionDaysForm = 36500   // 100 years
	// MaxRequestExpiryDays bounds how long an unanswered contact request waits (SPEC §9.1).
	// HDTP caps an invite at 90 days; a request left longer than a year is not being decided.
	MaxRequestExpiryDays = 365
)

// StorageRow is one account's storage policy, as the page shows it.
type StorageRow struct {
	// AccountID names the account the policy belongs to; Label is how the page names it.
	AccountID string `json:"account_id"`
	Label     string `json:"label"`
	// QuotaGiB is the media quota; 0 renders as the documented default.
	QuotaGiB int64 `json:"quota_gib"`
	// RetentionDays is 0 for unlimited, which is the default.
	RetentionDays int `json:"retention_days"`
	// RequestExpiryDays is how long an unanswered contact request, theirs or ours, waits
	// before it expires (SPEC §9.1): 30 unless the owner set another.
	RequestExpiryDays int `json:"request_expiry_days"`
}

// AdapterSetting is one stored adapter credential or option.
type AdapterSetting struct {
	// Key is the stored settings key (tunnel.<adapter>.<setting>). Secret says the value is a
	// credential, Set whether one is stored; the value itself is never returned.
	Key    string `json:"key"`
	Secret bool   `json:"secret"`
	Set    bool   `json:"set"`
}

// settingRow is one rendered control.
type settingRow struct {
	Key     string   `json:"key"`
	Value   string   `json:"value"`
	Locked  bool     `json:"locked"`
	Reason  string   `json:"reason"`
	Restart bool     `json:"restart"`
	Kind    string   `json:"kind"`    // text | bool | select
	Options []string `json:"options"` // for select
	Label   string   `json:"label"`
	Help    string   `json:"help"`
	// Pending: this value is saved but the node still runs Running.
	Pending bool   `json:"pending"`
	Running string `json:"running"`
}

// meta describes each knob for rendering. Kept next to the page because it is
// presentation: the authority on what a knob MEANS is core.
var settingMeta = map[string]struct{ label, help, kind string }{
	"public_url":      {"Public URL", "The externally reachable base other people's agents call. Each identity's address is built on it, and the wallet writes that address into the certificate it issues.", "text"},
	"tunnel":          {"Tunnel adapter", "How callers reach this node. The adapter decides the deployment mode — you do not set it.", "select"},
	"seal":            {"Sealed envelopes (X-HDTP-SEAL)", "Whether callers must seal. Applies immediately, and your card advertises exactly this.", "select"},
	"client_cert":     {"Client certificates", "preferred requests one; required refuses calls without one; off omits the request entirely.", "select"},
	"lan_connections": {"Accept LAN connections", "With a tunnel active, whether connections straight off the local network are served. Refusals are audited.", "bool"},
	"limit.contacts":  {"Contacts per identity", "How many contacts each identity here may hold (sent requests count). It also sizes the call budget: every contact may call at once, one call a second each. Empty restores 500.", "text"},
}

func (d SettingsDeps) rows(pending map[string]string) (reach, security []settingRow) {
	for _, e := range d.Effective() {
		m := settingMeta[e.Key]
		row := settingRow{
			Key: e.Key, Value: e.Value, Locked: e.Locked, Reason: e.Reason,
			Restart: core.RestartScoped(e.Key), Kind: m.kind, Label: m.label, Help: m.help,
		}
		if row.Label == "" {
			row.Label = e.Key
		}
		// A restart-scoped knob that was saved but not yet started shows what
		// the owner chose, and says what is still running.
		if v, ok := pending[e.Key]; ok && !e.Locked && v != e.Value {
			row.Value, row.Pending, row.Running = v, true, e.Value
		}
		switch e.Key {
		case "tunnel":
			row.Options = append([]string{""}, d.Adapters...)
		case "seal":
			row.Options = []string{"none", "optional", "required"}
		case "client_cert":
			row.Options = []string{"required", "preferred", "off"}
		}
		switch e.Key {
		case "public_url", "tunnel":
			reach = append(reach, row)
		default:
			// Budgets are a boundary control, so they belong with the other ones;
			// anything new lands here too rather than vanishing from the page.
			security = append(security, row)
		}
	}
	return reach, security
}

// render answers a settings request with the page's whole state, and the notice, error and probe verdict the request produced.
func (d SettingsDeps) render(w http.ResponseWriter, r *http.Request, notice string, isErr bool, verdict, detail string) {
	var pending map[string]string
	if d.Pending != nil {
		pending, _ = d.Pending(r.Context())
	}
	reach, security := d.rows(pending)
	var adapters []AdapterSetting
	if d.AdapterSettings != nil {
		adapters, _ = d.AdapterSettings(r.Context())
		sort.Slice(adapters, func(i, j int) bool { return adapters[i].Key < adapters[j].Key })
	}
	var paired map[string]bool
	if d.Paired != nil {
		paired, _ = d.Paired(r.Context())
	}
	var choices []AccountChoice
	if d.Accounts != nil {
		choices, _ = d.Accounts(r.Context())
	}
	var storage []StorageRow
	if d.Storage != nil {
		storage, _ = d.Storage(r.Context())
	}
	type presetRow struct {
		Name  string   `json:"name"`
		Perms []string `json:"perms"`
	}
	var presetRows []presetRow
	if d.Presets != nil {
		if set, err := d.Presets(r.Context()); err == nil {
			names := make([]string, 0, len(set))
			for n := range set {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				presetRows = append(presetRows, presetRow{Name: n, Perms: set[n]})
			}
		}
	}
	apiJSON(w, map[string]any{
		"show_storage": d.Storage != nil, "storage": storage,
		"show_presets": d.SavePreset != nil, "presets": presetRows,
		"preset_perms": contacts.AllPermissions,
		"show_pair":    d.Pair != nil, "paired": paired,
		"accounts": choices,
		"notice":   notice, "error": isErr,
		"reach": reach, "security": security,
		"adapter_settings": adapters, "adapters": d.Adapters,
		"show_probe":    d.Probe != nil,
		"probe_verdict": verdict, "probe_detail": detail,
	})
}

// MountSettingsPages registers the settings routes.
func MountSettingsPages(mux *http.ServeMux, d SettingsDeps) {
	mux.HandleFunc("GET /api/settings", d.getAPISettings)
	mux.HandleFunc("POST /settings", d.postSettings)
	mux.HandleFunc("POST /settings/adapter", d.postSettingsAdapter)

	if d.SaveStorage != nil {
		mux.HandleFunc("POST /settings/storage", d.postSettingsStorage)
	}

	if d.SavePreset != nil {
		mux.HandleFunc("POST /settings/presets", d.postSettingsPresets)
		mux.HandleFunc("POST /settings/presets/{name}/delete", d.postSettingsPresetsNameDelete)
	}

	if d.Pair != nil {
		mux.HandleFunc("POST /settings/pair", d.postSettingsPair)
		mux.HandleFunc("POST /settings/unpair", d.postSettingsUnpair)
	}

	if d.Probe != nil {
		mux.HandleFunc("POST /settings/probe", d.postSettingsProbe)
	}
}

// getAPISettings serves `GET /api/settings`.
func (d SettingsDeps) getAPISettings(w http.ResponseWriter, r *http.Request) {
	d.render(w, r, "", false, "", "")
}

// postSettings serves `POST /settings`.
func (d SettingsDeps) postSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Only knobs the resolved view says are editable are accepted. A locked
	// control is disabled in the browser, but the check that matters is
	// this one: a hand-crafted POST must not set a value the deployment
	// cannot honor.
	editable := map[string]bool{}
	for _, e := range d.Effective() {
		if !e.Locked {
			editable[e.Key] = true
		}
	}
	var saved, restart []string
	for _, key := range core.OwnerSettableKeys() {
		if !editable[key] {
			continue
		}
		// Only what the form actually submitted. A partial form must not
		// make the loop validate an absent field as empty and abort the
		// whole save half-done. Checkboxes are the exception: unchecked
		// means absent, which is exactly how a false arrives.
		if _, present := r.PostForm[key]; !present && settingMeta[key].kind != "bool" {
			continue
		}
		value := strings.TrimSpace(r.PostForm.Get(key))
		if settingMeta[key].kind == "bool" {
			value = "false"
			if r.PostForm.Get(key) == "true" {
				value = "true"
			}
		}
		// An ingress adapter without a completed pairing cannot start —
		// refuse it here, where the owner can act, rather than at the next
		// boot where it is a fatal startup error (SPEC §10.6).
		if key == "tunnel" && requiresPairing(value) {
			paired := map[string]bool{}
			if d.Paired != nil {
				paired, _ = d.Paired(r.Context())
			}
			if !paired[value] {
				d.audit("settings_save", "key:tunnel value:"+value, "bad_request")
				d.render(w, r, value+" needs a completed ingress pairing before it can be "+
					"selected — pair below first, which selects it for you", true, "", "")
				return
			}
		}
		if err := core.ValidateSetting(key, value); err != nil {
			d.audit("settings_save", "key:"+key, "bad_request")
			d.render(w, r, err.Error(), true, "", "")
			return
		}
		if err := d.Save(r.Context(), key, value); err != nil {
			d.audit("settings_save", "key:"+key, "error")
			d.render(w, r, "could not save "+key+": "+err.Error(), true, "", "")
			return
		}
		saved = append(saved, key)
		if core.RestartScoped(key) {
			restart = append(restart, key)
		}
	}
	if len(saved) == 0 {
		d.render(w, r, "Nothing to save.", false, "", "")
		return
	}
	notice := "Saved " + strings.Join(saved, ", ") + "."
	if len(restart) > 0 {
		notice += " Restart the node for " + strings.Join(restart, ", ") + " to take effect."
	}
	d.audit("settings_save", "keys:"+strings.Join(saved, ","), "ok")
	d.render(w, r, notice, false, "", "")
}

// postSettingsAdapter serves `POST /settings/adapter`.
func (d SettingsDeps) postSettingsAdapter(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(r.PostForm.Get("key"))
	value := r.PostForm.Get("value")
	// Two namespaces share this form because they are the same kind of thing:
	// a per-install value the owner supplies and a recipe or adapter reads.
	// `integration.<slug>.<name>` reaches a recipe as `$cfg.<name>`, which is
	// how a server that needs a value only this install knows — a CalDAV
	// collection URL, a calendar id — can be mapped at all.
	okKey := (strings.HasPrefix(key, "tunnel.") || strings.HasPrefix(key, "integration.")) &&
		strings.Count(key, ".") >= 2
	if !okKey {
		d.render(w, r, "a setting here is named tunnel.<adapter>.<setting> or "+
			"integration.<slug>.<name>", true, "", "")
		return
	}
	if err := d.Save(r.Context(), key, value); err != nil {
		d.audit("settings_save", "key:"+key, "error")
		d.render(w, r, "could not store "+key, true, "", "")
		return
	}
	// The key is audited; the value never is.
	d.audit("settings_save", "key:"+key, "ok")
	d.render(w, r, "Stored "+key+". Restart the node to use it.", false, "", "")
}

// postSettingsStorage serves `POST /settings/storage`.
func (d SettingsDeps) postSettingsStorage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	account := r.PostForm.Get("account")
	quota, err1 := strconv.ParseInt(strings.TrimSpace(r.PostForm.Get("quota_gib")), 10, 64)
	days, err2 := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("retention_days")))
	expiry, err3 := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("request_expiry_days")))
	if err1 != nil || err2 != nil || quota < 0 || days < 0 ||
		quota > MaxQuotaGiB || days > MaxRetentionDaysForm {
		d.render(w, r, "quota and retention are whole numbers, zero or more "+
			"(and within sane bounds — a window of a few hundred thousand days "+
			"is not a longer window, it is an overflow)", true, "", "")
		return
	}
	if err3 != nil || expiry < 1 || expiry > MaxRequestExpiryDays {
		d.render(w, r, fmt.Sprintf("an unanswered request waits a whole number of days, from 1 to %d", MaxRequestExpiryDays), true, "", "")
		return
	}
	if err := d.SaveStorage(r.Context(), account, quota, days, expiry); err != nil {
		d.audit("settings_storage", "account:"+account, "error")
		d.render(w, r, "could not save: "+err.Error(), true, "", "")
		return
	}
	d.audit("settings_storage",
		fmt.Sprintf("account:%s quota_gib:%d retention_days:%d request_expiry_days:%d", account, quota, days, expiry), "ok")
	notice := "Saved."
	if days > 0 {
		notice = fmt.Sprintf("Saved. Messages older than %d days will be deleted, permanently and locally.", days)
	}
	d.render(w, r, notice, false, "", "")
}

// postSettingsPresets serves `POST /settings/presets`.
func (d SettingsDeps) postSettingsPresets(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	perms := r.PostForm["perm"]
	if err := contacts.ValidatePreset(name, perms); err != nil {
		d.audit("settings_save", "key:"+contacts.PresetKeyPrefix+name, "bad_request")
		d.render(w, r, err.Error(), true, "", "")
		return
	}
	if err := d.SavePreset(r.Context(), name, perms); err != nil {
		d.audit("settings_save", "key:"+contacts.PresetKeyPrefix+name, "error")
		d.render(w, r, "could not save the preset: "+err.Error(), true, "", "")
		return
	}
	d.audit("settings_save", "key:"+contacts.PresetKeyPrefix+name+" perms:"+strings.Join(perms, ","), "ok")
	d.render(w, r, "Preset saved. It applies at the next approval or apply — grants already made keep their switches.", false, "", "")
}

// postSettingsPresetsNameDelete serves `POST /settings/presets/{name}/delete`.
func (d SettingsDeps) postSettingsPresetsNameDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	if err := d.DeletePreset(r.Context(), name); err != nil {
		d.audit("settings_save", "key:"+contacts.PresetKeyPrefix+name, "error")
		d.render(w, r, "could not delete the preset: "+err.Error(), true, "", "")
		return
	}
	d.audit("settings_save", "key:"+contacts.PresetKeyPrefix+name+" deleted:1", "ok")
	d.render(w, r, "Preset deleted. Contacts wearing it keep their switches; their label reads custom now. Deleting the last preset restores the documented four.", false, "", "")
}

// postSettingsPair serves `POST /settings/pair`.
func (d SettingsDeps) postSettingsPair(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	in := PairInput{
		PairURL:            strings.TrimSpace(r.PostForm.Get("pair_url")),
		Token:              strings.TrimSpace(r.PostForm.Get("token")),
		Subdomain:          strings.TrimSpace(r.PostForm.Get("subdomain")),
		Mode:               r.PostForm.Get("mode"),
		IngressFingerprint: strings.TrimSpace(r.PostForm.Get("ingress_fingerprint")),
		Account:            r.PostForm.Get("account"),
	}
	if in.PairURL == "" || in.Token == "" || in.Subdomain == "" {
		d.render(w, r, "a pairing needs the URL, the one-time token and a subdomain", true, "", "")
		return
	}
	res, err := d.Pair(r.Context(), in)
	if err != nil {
		msg := "pairing refused: " + err.Error()
		if res.Fingerprint != "" && in.IngressFingerprint != "" {
			msg += " (the ingress presented " + res.Fingerprint + ")"
		}
		d.render(w, r, msg, true, "", "")
		return
	}
	notice := "Paired as " + res.PublicName + " over " + res.Adapter +
		". Restart the node to serve there."
	if in.IngressFingerprint == "" {
		notice += " The ingress key is " + res.Fingerprint + " — check it against what you were given."
	}
	d.render(w, r, notice, false, "", "")
}

// postSettingsUnpair serves `POST /settings/unpair`.
func (d SettingsDeps) postSettingsUnpair(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if err := d.Unpair(r.Context(), r.PostForm.Get("adapter")); err != nil {
		d.render(w, r, "could not unpair: "+err.Error(), true, "", "")
		return
	}
	d.render(w, r, "Unpaired.", false, "", "")
}

// postSettingsProbe serves `POST /settings/probe`.
func (d SettingsDeps) postSettingsProbe(w http.ResponseWriter, r *http.Request) {
	verdict, detail := d.Probe(r.Context())
	d.audit("settings_probe", "public_url", verdict)
	d.render(w, r, "", false, verdict, detail)
}

// requiresPairing reports whether an adapter cannot start without a stored
// ingress pairing.
func requiresPairing(adapter string) bool {
	return adapter == "ingress-passthrough" || adapter == "ingress-terminate"
}

func (d SettingsDeps) audit(action, resource, outcome string) {
	if d.Audit != nil {
		d.Audit(action, resource, outcome)
	}
}

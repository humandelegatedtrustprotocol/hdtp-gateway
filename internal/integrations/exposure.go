package integrations

// Exposure sets (SPEC §6.5): what an integration actually serves. Immutable
// versions vM bound to a catalog snapshot vN; nothing exposed by default; every
// edit mints vM+1. The stale guard compares each entry's confirmed hash to the
// latest snapshot — drift or disappearance withholds the entry (`unavailable`)
// until the owner reconfirms, so a silently changed upstream can never widen
// what contacts reach.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// Serving modes (SPEC §6.6).
const (
	ModePassthrough = "passthrough"
	ModeMapped      = "mapped"
	ModeAgent       = "agent"
)

// ExposureEntry is one exposed capability.
type ExposureEntry struct {
	Tool          string `json:"tool"`               // upstream tool name in the bound snapshot
	Mode          string `json:"mode"`               // passthrough | mapped | agent
	ExposedName   string `json:"exposed_name"`       // default <slug>_<tool>, snake_case
	Recipe        string `json:"recipe,omitempty"`   // mapped entries: recipe binding (§6.7)
	Fallback      string `json:"fallback,omitempty"` // agent entries: passthrough|mapped|""
	ConfirmedHash string `json:"confirmed_hash"`     // tool hash the owner confirmed
	Stale         bool   `json:"stale,omitempty"`
}

// Exposures publishes, reconciles, and reads exposure sets.
type Exposures struct {
	Store store.Store
	Audit func(action, resource, outcome string)
	// OnChange fires whenever the served surface changes (publish, stale,
	// reconfirm): the serving layer drops the per-caller servers, so each
	// caller's next request lists the new surface (SPEC §6.5, §5.5).
	OnChange func(integrationID string)
}

func (e *Exposures) audit(action, resource, outcome string) {
	if e.Audit != nil {
		e.Audit(action, resource, outcome)
	}
}

func (e *Exposures) changed(integrationID string) {
	if e.OnChange != nil {
		e.OnChange(integrationID)
	}
}

// SnakeName normalizes a name to snake_case: lowercase, runs of non-alphanumerics
// collapse to single underscores.
func SnakeName(s string) string {
	var b strings.Builder
	us := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			if us && b.Len() > 0 {
				b.WriteByte('_')
			}
			us = false
			b.WriteRune(r)
		default:
			us = true
		}
	}
	return b.String()
}

func decodeEntries(entriesJSON string) ([]ExposureEntry, error) {
	var out []ExposureEntry
	if err := json.Unmarshal([]byte(entriesJSON), &out); err != nil {
		return nil, fmt.Errorf("integrations: %w", err)
	}
	return out, nil
}

// Publish validates entries against the LATEST catalog snapshot and mints vM+1.
func (e *Exposures) Publish(ctx context.Context, integrationID string, entries []ExposureEntry) (store.Exposure, error) {
	in, err := e.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, err
	}
	cat, err := e.Store.LatestCatalog(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, fmt.Errorf("integrations: no catalog snapshot to bind: %w", err)
	}
	var tools []ToolDef
	if err := json.Unmarshal([]byte(cat.Tools), &tools); err != nil {
		return store.Exposure{}, fmt.Errorf("integrations: %w", err)
	}
	hashes := make(map[string]string, len(tools))
	for _, t := range tools {
		hashes[t.Name] = t.Hash
	}
	// uniqueness spans the ACCOUNT's whole exposed surface (SPEC §6.5), not
	// just this integration's list
	seen, err := e.namesInUse(ctx, in)
	if err != nil {
		return store.Exposure{}, err
	}
	for i := range entries {
		en := &entries[i]
		h, ok := hashes[en.Tool]
		if !ok {
			return store.Exposure{}, fmt.Errorf("integrations: tool %q is not in catalog v%d", en.Tool, cat.Version)
		}
		switch en.Mode {
		case ModePassthrough, ModeMapped, ModeAgent:
		default:
			return store.Exposure{}, fmt.Errorf("integrations: unknown serving mode %q", en.Mode)
		}
		switch {
		case en.Fallback == "":
		case en.Mode != ModeAgent:
			return store.Exposure{}, fmt.Errorf("integrations: fallback is only for agent-answered entries")
		case en.Fallback != ModePassthrough && en.Fallback != ModeMapped:
			// falling back to agent-answered would be circular (SPEC §6.5)
			return store.Exposure{}, fmt.Errorf("integrations: fallback %q must be passthrough or mapped", en.Fallback)
		}
		if en.Mode == ModeMapped {
			if en.Recipe == "" {
				return store.Exposure{}, fmt.Errorf("integrations: mapped entry %q needs a recipe", en.Tool)
			}
			if en.ExposedName == "" {
				return store.Exposure{}, fmt.Errorf("integrations: mapped entry %q must name the PACT capability it implements", en.Tool)
			}
		} else if en.ExposedName == "" {
			en.ExposedName = SnakeName(in.Slug + "_" + en.Tool)
		} else {
			en.ExposedName = SnakeName(en.ExposedName)
		}
		if seen[en.ExposedName] {
			return store.Exposure{}, fmt.Errorf("integrations: exposed name %q is not unique", en.ExposedName)
		}
		seen[en.ExposedName] = true
		en.ConfirmedHash = h
		en.Stale = false
	}
	return e.mint(ctx, in, cat.Version, entries, "exposure_publish")
}

// namesInUse collects exposed names held by the account's OTHER integrations.
func (e *Exposures) namesInUse(ctx context.Context, in store.Integration) (map[string]bool, error) {
	seen := map[string]bool{}
	others, err := e.Store.ListIntegrations(ctx, in.AccountID)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		if o.ID == in.ID {
			continue
		}
		latest, err := e.Store.LatestExposure(ctx, o.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, err
		}
		ens, err := decodeEntries(latest.Entries)
		if err != nil {
			return nil, err
		}
		for _, en := range ens {
			seen[en.ExposedName] = true
		}
	}
	return seen, nil
}

func (e *Exposures) mint(ctx context.Context, in store.Integration, catalogVersion int64, entries []ExposureEntry, action string) (store.Exposure, error) {
	if entries == nil {
		entries = []ExposureEntry{}
	}
	blob, err := json.Marshal(entries)
	if err != nil {
		return store.Exposure{}, fmt.Errorf("integrations: %w", err)
	}
	version := int64(1)
	if latest, err := e.Store.LatestExposure(ctx, in.ID); err == nil {
		version = latest.Version + 1
	}
	exp, err := e.Store.InsertExposure(ctx, store.Exposure{
		IntegrationID: in.ID, Version: version, CatalogVersion: catalogVersion, Entries: string(blob),
	})
	if err != nil {
		e.audit(action, "account:"+in.AccountID+" integration:"+in.Slug, "error")
		return store.Exposure{}, err
	}
	e.audit(action, fmt.Sprintf("account:"+in.AccountID+" integration:%s exposure:v%d", in.Slug, version), "ok")
	e.changed(in.ID)
	return exp, nil
}

// Reconcile is the stale guard (SPEC §6.5): after a new snapshot, entries whose
// confirmed hash is missing or different become stale — withheld from every
// caller until reconfirmed. Minting happens only when staleness actually changes.
func (e *Exposures) Reconcile(ctx context.Context, integrationID string) (store.Exposure, bool, error) {
	in, err := e.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, false, err
	}
	latest, err := e.Store.LatestExposure(ctx, integrationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Exposure{}, false, nil // nothing exposed: nothing to guard
		}
		// a transient store failure must NOT silently skip the guard
		return store.Exposure{}, false, err
	}
	cat, err := e.Store.LatestCatalog(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, false, err
	}
	var tools []ToolDef
	if err := json.Unmarshal([]byte(cat.Tools), &tools); err != nil {
		return store.Exposure{}, false, fmt.Errorf("integrations: %w", err)
	}
	hashes := make(map[string]string, len(tools))
	for _, t := range tools {
		hashes[t.Name] = t.Hash
	}
	entries, err := decodeEntries(latest.Entries)
	if err != nil {
		return store.Exposure{}, false, err
	}
	dirty := false
	for i := range entries {
		h, ok := hashes[entries[i].Tool]
		stale := !ok || h != entries[i].ConfirmedHash
		if stale != entries[i].Stale {
			entries[i].Stale = stale
			dirty = true
			outcome := "ok"
			if stale {
				e.audit("exposure_stale", fmt.Sprintf("account:"+in.AccountID+" integration:%s:%s", in.Slug, entries[i].ExposedName), outcome)
			}
		}
	}
	if !dirty {
		return latest, false, nil
	}
	exp, err := e.mint(ctx, in, cat.Version, entries, "exposure_reconcile")
	if err != nil {
		return store.Exposure{}, false, err
	}
	return exp, true, nil
}

// Reconfirm re-binds entries to the latest snapshot (SPEC §6.5 one-click
// reconfirm): named tools — or all stale ones when names is empty — get their
// confirmed hash updated and staleness cleared, in a fresh vM+1. Entries whose
// tool no longer exists in the snapshot cannot be reconfirmed and stay stale.
func (e *Exposures) Reconfirm(ctx context.Context, integrationID string, names []string) (store.Exposure, error) {
	in, err := e.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, err
	}
	latest, err := e.Store.LatestExposure(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, err
	}
	cat, err := e.Store.LatestCatalog(ctx, integrationID)
	if err != nil {
		return store.Exposure{}, err
	}
	var tools []ToolDef
	if err := json.Unmarshal([]byte(cat.Tools), &tools); err != nil {
		return store.Exposure{}, fmt.Errorf("integrations: %w", err)
	}
	hashes := make(map[string]string, len(tools))
	for _, t := range tools {
		hashes[t.Name] = t.Hash
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	entries, err := decodeEntries(latest.Entries)
	if err != nil {
		return store.Exposure{}, err
	}
	for i := range entries {
		en := &entries[i]
		if !en.Stale || (len(want) > 0 && !want[en.ExposedName]) {
			continue
		}
		h, ok := hashes[en.Tool]
		if !ok {
			continue // tool vanished upstream: stays stale until removed or it returns
		}
		en.ConfirmedHash = h
		en.Stale = false
		e.audit("exposure_reconfirm", fmt.Sprintf("account:"+in.AccountID+" integration:%s:%s", in.Slug, en.ExposedName), "ok")
	}
	return e.mint(ctx, in, cat.Version, entries, "exposure_publish")
}

// AllEntries returns the latest set including stale entries (the portal shows
// them with their diff and offers reconfirm — SPEC §6.5).
func (e *Exposures) AllEntries(ctx context.Context, integrationID string) ([]ExposureEntry, error) {
	latest, err := e.Store.LatestExposure(ctx, integrationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return decodeEntries(latest.Entries)
}

// ActiveEntries is what callers may see and call right now: the latest exposure
// set minus stale entries (they fail `unavailable` and vanish from tools/list).
func (e *Exposures) ActiveEntries(ctx context.Context, integrationID string) ([]ExposureEntry, error) {
	entries, err := e.AllEntries(ctx, integrationID)
	if err != nil || entries == nil {
		return nil, err
	}
	out := make([]ExposureEntry, 0, len(entries))
	for _, en := range entries {
		if !en.Stale {
			out = append(out, en)
		}
	}
	return out, nil
}

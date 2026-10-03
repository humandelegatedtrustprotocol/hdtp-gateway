package contacts

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Presets are owner-defined bundles (HDTP §8): assigned at approval time,
// adjustable per contact afterwards, and — since 1.2 — editable by the owner.
// The four documented defaults are in force until the owner writes their own;
// the FIRST owner write seeds all four as rows, so editing one bundle can
// never silently delete the others.

// PresetSet is one node's bundles by name.
type PresetSet map[string][]string

// DefaultPresets is what an untuned node grants — the table HDTP §8 documents.
var DefaultPresets = PresetSet{
	"basic":  {"message.text"},
	"work":   {"message.text", "calendar.availability", "calendar.book"},
	"friend": {"message.text", "message.media", "status.view", "calendar.availability", "calendar.book"},
	"family": {"message.text", "message.media", "status.view", "calendar.availability", "calendar.book"},
}

// PresetKeyPrefix is where owner bundles live in the settings store, one row
// per bundle (`preset.<name>` = comma-joined permissions) — the adapter-settings
// pattern: dotted keys, read by whoever needs them, no config field.
const PresetKeyPrefix = "preset."

// SettingsReader is the slice of the store preset resolution needs.
type SettingsReader interface {
	ListSettings(ctx context.Context) ([]store.Setting, error)
}

// LoadPresets resolves the node's bundles: every `preset.*` row when any
// exist, the compiled-in defaults when none do. It ALWAYS returns a usable
// set — on a store error the defaults are in force, because "no presets" is
// not a state the approval flow can work in.
func LoadPresets(ctx context.Context, st SettingsReader) PresetSet {
	if st == nil {
		return DefaultPresets
	}
	rows, err := st.ListSettings(ctx)
	if err != nil {
		return DefaultPresets
	}
	set := PresetSet{}
	for _, r := range rows {
		if name, ok := strings.CutPrefix(r.Key, PresetKeyPrefix); ok && name != "" {
			set[name] = splitPerms(r.Value)
		}
	}
	if len(set) == 0 {
		return DefaultPresets
	}
	return set
}

func splitPerms(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Names is the set's names in a stable order — three pages used to build this
// list for themselves and one iterated a map directly.
func (ps PresetSet) Names() []string {
	out := make([]string, 0, len(ps))
	for name := range ps {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Holds reports whether perms is still the bundle called name. A preset is a
// claim about the whole core switchboard, so it stays true only while the core
// grant is exactly that bundle: hand-toggle one row and the label has to go,
// or the record says "family" over a grant nobody would call family.
//
// Integration grants (SPEC §6.4) are outside the comparison in both
// directions. No bundle names them, so they neither earn a preset nor break
// one — the same reason applying a preset deliberately preserves them.
//
// The empty name is the cleared state and holds for nothing: a bespoke grant
// wears no label.
func (ps PresetSet) Holds(name string, perms []string) bool {
	want, ok := ps[name]
	if !ok {
		return false
	}
	core := map[string]bool{}
	for _, p := range AllPermissions {
		core[p] = true
	}
	have := map[string]bool{}
	for _, p := range perms {
		if core[p] {
			have[p] = true
		}
	}
	// The wanted bundle dedupes through the same core filter, so a duplicated
	// or non-core entry in a stored bundle cannot fake a size.
	wantSet := map[string]bool{}
	for _, p := range want {
		if core[p] {
			wantSet[p] = true
		}
	}
	if len(have) != len(wantSet) {
		return false
	}
	for p := range wantSet {
		if !have[p] {
			return false
		}
	}
	return true
}

var presetName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// ValidatePreset is the write-side gate: a name the portal can render and
// core permissions only. Integration grants are deliberately outside bundles
// (SPEC §6.4) — a bundle naming one would grant and revoke a capability the
// preset control never mentions.
func ValidatePreset(name string, perms []string) error {
	if !presetName.MatchString(name) {
		return fmt.Errorf("a preset name is 1-32 of a-z, 0-9, '-', '_', starting with a letter")
	}
	if name == "none" {
		return fmt.Errorf("%q is the portal's word for no preset", name)
	}
	if len(perms) == 0 {
		return fmt.Errorf("a preset grants at least one permission; delete it instead of emptying it")
	}
	core := map[string]bool{}
	for _, p := range AllPermissions {
		core[p] = true
	}
	for _, p := range perms {
		if !core[p] {
			return fmt.Errorf("%q is not a core permission; integration grants stay per-contact", p)
		}
	}
	return nil
}

// AllPermissions is the switchboard's row order (SPEC §8, HDTP §8).
var AllPermissions = []string{
	"message.text", "message.media", "status.view", "calendar.availability", "calendar.book",
}

// integrationGrant is an integration's permission name as a grant carries it: `integration.` and a
// slug, and only a slug — no dot, no wildcard, so no grant can name them all (batondeck's
// isIntegrationPermission, the same expression).
var integrationGrant = regexp.MustCompile(`^integration\.[a-z0-9][a-z0-9-]{0,62}$`)

// TheirPermissions is what a peer says it granted us (contact_accepted, HDTP §6.2), as this node
// records it: only what a grant can be — HDTP §8's names (AllPermissions) and integration.<slug> —
// each once, in the order given. Anything else a peer sends is dropped at intake.
func TheirPermissions(in []string) []string {
	core := map[string]bool{}
	for _, p := range AllPermissions {
		core[p] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range in {
		if seen[p] || !(core[p] || integrationGrant.MatchString(p)) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

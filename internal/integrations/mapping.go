package integrations

// The field-mapping DSL (SPEC §6.7): recipes bind provider fields to upstream
// request/response fields with field-to-field references and constants —
// NOTHING else. No expressions, no conditionals, no scripting: anything
// smarter lives in provider code where it is testable and cannot be smuggled
// in via configuration.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Recipe is one per-server map (SPEC §6.7): which upstream tools implement
// which HDTP capabilities, and how fields line up.
type Recipe struct {
	Name         string             `json:"name"`              // the key ExposureEntry.Recipe refers to
	Server       string             `json:"server"`            // the upstream the recipe was written for
	Description  string             `json:"description"`       // prose for the owner
	Caveats      []string           `json:"caveats,omitempty"` // known gaps, shown to the owner
	Capabilities map[string]Binding `json:"capabilities"`      // HDTP capability name -> binding
}

// Binding maps one HDTP capability onto one upstream tool.
type Binding struct {
	Tool string `json:"tool"`
	// Kind tells the provider which computation applies:
	// check_availability: "suggest" (upstream returns candidate times) or
	// "freebusy" (provider computes slots from busy blocks); book_slot:
	// "create"; cancel_booking: "delete"; get_status: "status".
	Kind string `json:"kind"`
	// Args builds the upstream request: upstream field ← "$provider_field"
	// reference or a literal constant string.
	Args map[string]string `json:"args,omitempty"`
	// Out extracts from the upstream response: provider field ← dot.path.
	Out map[string]string `json:"out,omitempty"`
}

// BuildArgs assembles upstream arguments: "$name" pulls from fields (an error
// when absent — a recipe cannot invent data), anything else is a constant.
func BuildArgs(b Binding, fields map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(b.Args))
	for upField, ref := range b.Args {
		if strings.HasPrefix(ref, "$") {
			v, ok := fields[ref[1:]]
			if !ok {
				return nil, fmt.Errorf("integrations: recipe references unknown field %q", ref)
			}
			out[upField] = v
			continue
		}
		out[upField] = ref
	}
	return out, nil
}

// Lookup walks a dot path ("calendars.primary.busy") through decoded JSON.
func Lookup(v any, path string) (any, bool) {
	cur := v
	if path == "" || path == "." {
		return cur, true
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// LookupString is Lookup for string-valued fields.
func LookupString(v any, path string) (string, bool) {
	got, ok := Lookup(v, path)
	if !ok {
		return "", false
	}
	s, ok := got.(string)
	return s, ok
}

// DecodeRecipe parses and structurally validates one recipe document.
func DecodeRecipe(data []byte) (Recipe, error) {
	var r Recipe
	if err := json.Unmarshal(data, &r); err != nil {
		return Recipe{}, fmt.Errorf("integrations: recipe: %w", err)
	}
	if r.Name == "" || len(r.Capabilities) == 0 {
		return Recipe{}, fmt.Errorf("integrations: recipe %q needs a name and capabilities", r.Name)
	}
	for capName, b := range r.Capabilities {
		if b.Tool == "" || b.Kind == "" {
			return Recipe{}, fmt.Errorf("integrations: recipe %s capability %s needs tool and kind", r.Name, capName)
		}
	}
	return r, nil
}

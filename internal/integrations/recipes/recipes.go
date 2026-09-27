// Package recipes embeds the shipped per-server recipe documents (SPEC §6.7).
package recipes

import (
	"embed"
	"fmt"

	"github.com/pact-cloud/pact-gateway/internal/integrations"
)

//go:embed *.json
var files embed.FS

// All decodes every shipped recipe, keyed by name.
func All() (map[string]integrations.Recipe, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := map[string]integrations.Recipe{}
	for _, e := range entries {
		data, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		r, err := integrations.DecodeRecipe(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out[r.Name] = r
	}
	return out, nil
}

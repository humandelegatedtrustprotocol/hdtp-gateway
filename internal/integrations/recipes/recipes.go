// Package recipes embeds the shipped per-server recipe documents (SPEC §6.7).
package recipes

import (
	"embed"
	"fmt"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

//go:embed *.json
var files embed.FS

// All decodes every embedded *.json recipe, keyed by the recipe's own name.
// It fails on the first file integrations.DecodeRecipe refuses, naming the
// file; a second file with the same name silently replaces the first.
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

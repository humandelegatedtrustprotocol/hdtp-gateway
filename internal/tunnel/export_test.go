package tunnel

import (
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core"
)

// derivesEdge reports whether configuring this adapter puts a node in edge mode,
// through the one derivation the node runs (core.Config.Derive, SPEC §10.1).
func derivesEdge(t *testing.T, name string) (bool, error) {
	t.Helper()
	dir := t.TempDir()
	c, err := core.Load("", func(k string) (string, bool) {
		v, ok := map[string]string{"PACT_DATA_DIR": dir, "PACT_TUNNEL": name}[k]
		return v, ok
	})
	if err != nil {
		return false, err
	}
	return c.Mode == core.ModeEdge, nil
}

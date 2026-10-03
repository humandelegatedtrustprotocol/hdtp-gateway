package store_test

import (
	"path/filepath"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store/conformance"
)

func TestSQLiteConformance(t *testing.T) {
	conformance.Run(t, func(t *testing.T) conformance.Migratable {
		s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

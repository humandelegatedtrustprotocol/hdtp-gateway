package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/contacts"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

func presetSvc(t *testing.T) (*settingsService, store.Store) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &settingsService{store: st, now: func() time.Time { return time.Unix(1756000000, 0) }}, st
}

// PACT §8: presets are owner-editable. The first write seeds every resolved
// bundle as rows so editing one cannot silently delete the others; deleting
// the last row restores the documented four.
func TestPresetEditingSeedsAndRestores(t *testing.T) {
	s, st := presetSvc(t)
	ctx := context.Background()

	// First write: the edited bundle plus the seeded three others.
	if err := s.savePreset(ctx, "work", []string{"message.text", "calendar.book"}); err != nil {
		t.Fatal(err)
	}
	set := contacts.LoadPresets(ctx, st)
	if len(set) != 4 {
		t.Fatalf("first write did not seed the set: %v", set.Names())
	}
	if !set.Holds("work", []string{"message.text", "calendar.book"}) {
		t.Fatalf("the edit was lost: %v", set["work"])
	}
	if !set.Holds("family", contacts.DefaultPresets["family"]) {
		t.Fatalf("a sibling bundle was not seeded: %v", set["family"])
	}

	// A new bundle joins; validation still gates.
	if err := s.savePreset(ctx, "close", []string{"message.text", "message.media"}); err != nil {
		t.Fatal(err)
	}
	if err := s.savePreset(ctx, "bad", []string{"integration.x"}); err == nil {
		t.Fatal("an integration grant entered a bundle")
	}
	if got := contacts.LoadPresets(ctx, st); len(got) != 5 {
		t.Fatalf("bundles: %v", got.Names())
	}

	// Deleting down to zero restores the documented defaults.
	for _, n := range contacts.LoadPresets(ctx, st).Names() {
		if err := s.deletePreset(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if got := contacts.LoadPresets(ctx, st); len(got) != 4 || !got.Holds("basic", []string{"message.text"}) {
		t.Fatalf("deleting the last row did not restore the defaults: %v", got.Names())
	}
}

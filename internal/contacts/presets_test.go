package contacts

import (
	"context"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// A preset is a label over the core switchboard. It has to stay true on its own
// merits, because every surface that shows it — the contact page, the chat panel
// — is asserting to the owner that this contact holds that bundle.
func TestPresetHolds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		perms []string
		want  bool
	}{
		{"basic", []string{"message.text"}, true},
		{"basic", []string{"message.text", "calendar.book"}, false},
		{"basic", nil, false},
		{"work", []string{"message.text", "calendar.availability", "calendar.book"}, true},
		{"work", []string{"calendar.availability", "calendar.book"}, false},
		// An integration grant is outside the comparison: no bundle names one,
		// and applying a preset deliberately keeps it.
		{"basic", []string{"message.text", "integration.batondeck"}, true},
		{"family", []string{"message.text", "message.media", "status.view",
			"calendar.availability", "calendar.book", "integration.batondeck"}, true},
		// The cleared state is a state: it labels nothing, including the empty grant.
		{"", nil, false},
		{"", []string{"message.text"}, false},
		{"nonesuch", []string{"message.text"}, false},
		// Duplicates in the stored grant must not fake a bundle's size.
		{"work", []string{"message.text", "message.text", "calendar.book"}, false},
	} {
		if got := PresetHolds(tc.name, tc.perms); got != tc.want {
			t.Errorf("PresetHolds(%q, %v) = %v, want %v", tc.name, tc.perms, got, tc.want)
		}
	}
}

// PACT §8 since 1.2: presets are owner-editable. Rows are the complete set the
// moment any exist; none means the documented four; errors degrade to the four
// rather than to "no presets", which the approval flow cannot work in.
func TestLoadPresetsResolution(t *testing.T) {
	ctx := context.Background()

	if set := LoadPresets(ctx, nil); len(set) != 4 || !set.Holds("basic", []string{"message.text"}) {
		t.Fatalf("nil store must mean the defaults: %v", set.Names())
	}
	if set := LoadPresets(ctx, errReader{}); len(set) != 4 {
		t.Fatalf("a store error must degrade to the defaults: %v", set.Names())
	}
	if set := LoadPresets(ctx, listReader{}); len(set) != 4 {
		t.Fatalf("no rows must mean the defaults: %v", set.Names())
	}
	custom := listReader{{Key: "preset.close", Value: "message.text,message.media"}, {Key: "tunnel", Value: "x"}}
	set := LoadPresets(ctx, custom)
	if len(set) != 1 || !set.Holds("close", []string{"message.text", "message.media"}) {
		t.Fatalf("rows must be the complete set: %v", set)
	}
	if set.Holds("basic", []string{"message.text"}) {
		t.Fatal("a default survived alongside owner rows")
	}
}

type errReader struct{}

func (errReader) ListSettings(context.Context) ([]store.Setting, error) {
	return nil, context.DeadlineExceeded
}

type listReader []store.Setting

func (l listReader) ListSettings(context.Context) ([]store.Setting, error) { return l, nil }

func TestValidatePreset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		perms []string
		ok    bool
	}{
		{"close", []string{"message.text"}, true},
		{"a-b_2", AllPermissions, true},
		{"None", []string{"message.text"}, false},           // uppercase
		{"none", []string{"message.text"}, false},           // the UI sentinel
		{"close", nil, false},                               // empty grant
		{"close", []string{"integration.batondeck"}, false}, // outside bundles
		{"", []string{"message.text"}, false},
		{"waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay-too-long", []string{"message.text"}, false},
	} {
		err := ValidatePreset(tc.name, tc.perms)
		if tc.ok && err != nil {
			t.Errorf("%q/%v refused: %v", tc.name, tc.perms, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%q/%v accepted", tc.name, tc.perms)
		}
	}
}

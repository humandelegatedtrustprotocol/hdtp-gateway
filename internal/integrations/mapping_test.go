package integrations

import "testing"

func TestBuildArgsFieldsAndConstants(t *testing.T) {
	b := Binding{Args: map[string]string{
		"action": "create", "summary": "$subject", "start": "$start",
	}}
	got, err := BuildArgs(b, map[string]any{"subject": "Tea", "start": "2026-08-25T10:00:00Z"})
	if err != nil || got["action"] != "create" || got["summary"] != "Tea" || got["start"] != "2026-08-25T10:00:00Z" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := BuildArgs(Binding{Args: map[string]string{"x": "$missing"}}, nil); err == nil {
		t.Fatal("unknown field reference accepted")
	}
}

func TestLookupDotPaths(t *testing.T) {
	v := map[string]any{"calendars": map[string]any{"primary": map[string]any{"busy": []any{"b"}}}}
	got, ok := Lookup(v, "calendars.primary.busy")
	if !ok || len(got.([]any)) != 1 {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := Lookup(v, "calendars.missing.busy"); ok {
		t.Fatal("missing path resolved")
	}
	if s, ok := LookupString(map[string]any{"id": "e1"}, "id"); !ok || s != "e1" {
		t.Fatal("string lookup")
	}
}

func TestDecodeRecipeValidates(t *testing.T) {
	if _, err := DecodeRecipe([]byte(`{"name":"x"}`)); err == nil {
		t.Fatal("empty capabilities accepted")
	}
	if _, err := DecodeRecipe([]byte(`{"name":"x","capabilities":{"book_slot":{"tool":"t"}}}`)); err == nil {
		t.Fatal("kind-less binding accepted")
	}
}

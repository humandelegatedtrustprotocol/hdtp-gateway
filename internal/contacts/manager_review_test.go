package contacts

import (
	"strings"
	"testing"
)

// Coordinator item 4 (review 2026-09-28). What a peer says it granted us (contact_accepted's
// `permissions`, PACT §6.2) was stored as it came: any strings, repeated, up to 64 of them. It is
// filtered at intake to what a grant can be - PACT §8's names and integration.<slug>, the slug as
// the cloud holds it - and deduplicated, first occurrence first.
func TestTheirPermissionsAreFilteredAtIntake(t *testing.T) {
	in := []string{"message.text", "message.text", "calendar.book", "admin", "integration.cal", "integration.", "integration.*",
		"integration.Cal", "integration.a.b", "integration.-x", "integration." + strings.Repeat("a", 64), "integration." + strings.Repeat("a", 63),
		"<script>", "", "integration.cal"}
	got := strings.Join(TheirPermissions(in), " ")
	want := "message.text calendar.book integration.cal integration." + strings.Repeat("a", 63)
	if got != want {
		t.Fatalf("filtered to %q, want %q", got, want)
	}
	if TheirPermissions(nil) == nil {
		t.Fatal("no permissions is an empty list, not nil")
	}
}

// The same at the door: contact_accepted's permissions are recorded filtered.
func TestAnAcceptanceRecordsOnlyWhatAGrantCanBe(t *testing.T) {
	m, st, ctx, acct := newInitEnv(t)
	card, fpr, spki := peerCard(t, "Bob")
	if err := m.Initiated(ctx, acct, fpr, card, spki, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.ContactAccepted(ctx, acct, fpr, card, []string{"message.text", "message.text", "root", "integration.*", "integration.cal"}); err != nil {
		t.Fatal(err)
	}
	c, err := st.GetContact(ctx, acct, fpr)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.TheirPermissions, " "); got != "message.text integration.cal" {
		t.Fatalf("recorded %q", got)
	}
}

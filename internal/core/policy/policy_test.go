package policy

import "testing"

func TestTierFor(t *testing.T) {
	cases := []struct {
		status string
		found  bool
		want   Tier
	}{
		{"", false, TierGuest}, // unknown fingerprint
		{"active", true, TierContact},
		{"pending_out", true, TierPending}, // we invited them; they answer accept/reject
		{"pending_in", true, TierGuest},    // they asked us; nothing until approval
		{"blocked", true, TierGuest},       // silently indistinguishable from stranger
	}
	for _, tc := range cases {
		if got := TierFor(tc.status, tc.found); got != tc.want {
			t.Fatalf("TierFor(%q,%v) = %v, want %v", tc.status, tc.found, got, tc.want)
		}
	}
}

func TestAllowExactTierAndPermission(t *testing.T) {
	contact := Caller{Tier: TierContact, Permissions: map[string]bool{"message.text": true}}
	guest := Caller{Tier: TierGuest}
	if Allow(guest, Rule{Tier: TierContact, Permission: ""}) {
		t.Fatal("guest allowed a contact tool")
	}
	if Allow(contact, Rule{Tier: TierGuest}) {
		t.Fatal("tiers are exact surfaces, not ranks: contact must not see guest tools")
	}
	if !Allow(contact, Rule{Tier: TierContact, Permission: "message.text"}) {
		t.Fatal("granted permission denied")
	}
	if Allow(contact, Rule{Tier: TierContact, Permission: "calendar.book"}) {
		t.Fatal("ungranted permission allowed")
	}
	if !Allow(contact, Rule{Tier: TierContact}) {
		t.Fatal("always-available contact tool denied")
	}
}

func TestBlockedForbidOverridesEverything(t *testing.T) {
	// even a caller that would otherwise pass every permit is denied outright
	blocked := Caller{
		Tier:        TierContact,
		Blocked:     true,
		Permissions: map[string]bool{"message.text": true},
	}
	if Allow(blocked, Rule{Tier: TierContact, Permission: "message.text"}) {
		t.Fatal("blocked caller allowed: forbid must override permit")
	}
	if Allow(blocked, Rule{Tier: TierContact}) {
		t.Fatal("blocked caller allowed an always-tool")
	}
	if Allow(blocked, Rule{Tier: TierPending}) {
		t.Fatal("blocked caller allowed a pending tool")
	}
	// ...but the GUEST surface is the one thing the forbid must not touch.
	// SPEC §5.4/§9.1 require a blocked caller to be served exactly as an unknown
	// one, and the tier the resolver actually assigns a blocked contact IS guest.
	// An empty tools/list where a stranger sees two is precisely the oracle the
	// spec forbids, so the two must agree tool for tool.
	stranger := Caller{Tier: TierGuest}
	demoted := Caller{Tier: TierFor("blocked", true), Blocked: true,
		Permissions: map[string]bool{"message.text": true}}
	for _, r := range []Rule{
		{Tier: TierGuest}, {Tier: TierPending},
		{Tier: TierContact}, {Tier: TierContact, Permission: "message.text"},
	} {
		if Allow(demoted, r) != Allow(stranger, r) {
			t.Fatalf("blocked and unknown differ on %+v", r)
		}
	}
	if !Allow(demoted, Rule{Tier: TierGuest}) {
		t.Fatal("demoted blocked caller lost the guest surface")
	}
	if Allow(demoted, Rule{Tier: TierContact, Permission: "message.text"}) {
		t.Fatal("demoted blocked caller reached a contact tool")
	}
}

func TestOwnerManageMatrix(t *testing.T) {
	admin := OwnerCtx{OwnerID: "o1", AdminAccounts: []string{"acct-1", "acct-3"}}
	if !AllowOwnerManage(admin, "acct-1") {
		t.Fatal("admin denied on own account")
	}
	if AllowOwnerManage(admin, "acct-2") {
		t.Fatal("admin allowed on foreign account")
	}
	nobody := OwnerCtx{OwnerID: "o2"}
	if AllowOwnerManage(nobody, "acct-1") {
		t.Fatal("non-member allowed")
	}
}

func TestGuestScopeUnderCedar(t *testing.T) {
	guest := Caller{Tier: TierGuest}
	if !Allow(guest, Rule{Tier: TierGuest}) {
		t.Fatal("guest denied guest tool")
	}
	if Allow(guest, Rule{Tier: TierContact, Permission: "message.text"}) {
		t.Fatal("guest allowed contact tool")
	}
	if Allow(guest, Rule{Tier: TierPending}) {
		t.Fatal("guest allowed pending tool")
	}
}

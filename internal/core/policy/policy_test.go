package policy

import (
	"context"
	"errors"
	"slices"
	"testing"
)

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

type listed struct {
	ms  []Membership
	err error
	n   int
}

func (l *listed) OwnerMemberships(context.Context, string) ([]Membership, error) {
	l.n++
	return l.ms, l.err
}

func TestOwnerScope(t *testing.T) {
	ctx := context.Background()
	l := &listed{ms: []Membership{{AccountID: "a1", Role: "admin"}, {AccountID: "a2", Role: "admin"}, {AccountID: "a3", Role: "viewer"}}}
	if sc, err := OwnerScope(ctx, l, "o1", ""); err != nil || !slices.Equal(sc.AdminAccounts, []string{"a1", "a2"}) || sc.OwnerID != "o1" {
		t.Fatalf("scope: %+v %v, want the admin memberships", sc, err)
	}
	if sc, err := OwnerScope(ctx, l, "o1", "a2"); err != nil || !slices.Equal(sc.AdminAccounts, []string{"a2"}) {
		t.Fatalf("narrowed: %+v %v, want a2 alone", sc, err)
	}
	if sc, err := OwnerScope(ctx, l, "o1", "a3"); err != nil || len(sc.AdminAccounts) != 0 {
		t.Fatalf("narrowed to a non-admin membership: %+v %v, want none", sc, err)
	}
	n := l.n
	if sc, err := OwnerScope(ctx, l, "", ""); err != nil || len(sc.AdminAccounts) != 0 || l.n != n {
		t.Fatalf("no owner: %+v %v, listed %d times, want an empty scope and no list", sc, err, l.n-n)
	}
	l.err = errors.New("unreadable")
	if _, err := OwnerScope(ctx, l, "o1", ""); err == nil {
		t.Fatal("an unreadable list gave a scope")
	}
}

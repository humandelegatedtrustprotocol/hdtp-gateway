package ownermcp

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/internalui/auth"
)

// N-06 and N-21 on the agent's surface: approval tells the peer the grant the row holds, within a
// bound. It told them `bundles[preset]` — nothing at all when no preset was named, though a request
// through an invite holds the invite's grant — and on the tool call's own context.
func TestApproveContactTellsTheRowsGrantWithinABudget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	invited := []string{"message.text", "status.view"}
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:inv", Status: "pending_in",
		Preset: "work", Permissions: invited, InviteID: "inv-1"}); err != nil {
		t.Fatal(err)
	}
	var granted []string
	var allowed time.Duration
	calls := 0
	e.deps.Approved = func(ctx context.Context, _, _ string, g []string) error {
		calls++
		granted = g
		if dl, ok := ctx.Deadline(); ok {
			allowed = time.Until(dl)
		}
		return nil
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	if out, isErr := callJSON(t, cs, "approve_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:inv"}); isErr {
		t.Fatalf("approve_contact: %s", out)
	}
	c, _ := e.st.GetContact(ctx, e.acctA, "sha256:inv")
	if calls != 1 || !slices.Equal(granted, c.Permissions) || len(granted) != len(invited) {
		t.Fatalf("the row grants %v and the peer was told %v", c.Permissions, granted)
	}
	if allowed <= 0 || allowed > 6*time.Second {
		t.Fatalf("the call to the peer was allowed %v; want a bound of a few seconds", allowed)
	}
}

// N-07: set_permissions saves against the same switchboard the portal does. It kept only the core
// five and answered "ok", so a grant the contact already held — an integration the owner granted in
// the portal — was dropped by an agent that never mentioned it, and a name nobody offers was
// silently thrown away instead of refused.
func TestSetPermissionsKeepsWhatTheSwitchboardOffersAndRefusesTheRest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:c", Status: "active",
		Permissions: []string{"message.text", "integration.cal"}}); err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	if out, isErr := callJSON(t, cs, "set_permissions", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:c",
		"permissions": []string{"message.text", "status.view", "integration.cal"}}); isErr {
		t.Fatalf("set_permissions: %s", out)
	}
	c, _ := e.st.GetContact(ctx, e.acctA, "sha256:c")
	if !slices.Contains(c.Permissions, "integration.cal") || !slices.Contains(c.Permissions, "status.view") {
		t.Fatalf("the held integration grant was dropped: %v", c.Permissions)
	}
	out, isErr := callJSON(t, cs, "set_permissions", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:c",
		"permissions": []string{"message.text", "integration.nobody-serves-this"}})
	if !isErr || !strings.Contains(out, "bad_request") {
		t.Fatalf("a permission nobody offers was answered %q (error=%v); want bad_request", out, isErr)
	}
	if c2, _ := e.st.GetContact(ctx, e.acctA, "sha256:c"); !slices.Equal(c2.Permissions, c.Permissions) {
		t.Fatalf("a refused save changed the grant: %v -> %v", c.Permissions, c2.Permissions)
	}
}

// N-01, N-02, P-13 on the agent's surface: an agent can decide everything a person can about
// who reaches the account — reject, block, unblock, remove, list and revoke invites — through the
// same lifecycle the portal calls, and a rejected requester and a removed contact are told.
func TestTheAgentRunsTheWholeContactLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var rejected, removed []string
	var unbounded []string // a courtesy call made with no deadline
	bounded := func(ctx context.Context, what string) {
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > 6*time.Second {
			unbounded = append(unbounded, what)
		}
	}
	e.deps.Rejected = func(ctx context.Context, _, fpr string) error {
		bounded(ctx, "reject")
		rejected = append(rejected, fpr)
		return nil
	}
	e.deps.Removed = func(ctx context.Context, _, fpr string) error {
		bounded(ctx, "remove")
		removed = append(removed, fpr)
		return nil
	}
	for _, c := range []store.Contact{
		{AccountID: e.acctA, Fingerprint: "sha256:asker", Status: "pending_in"},
		{AccountID: e.acctA, Fingerprint: "sha256:friend", Status: "active", Preset: "friend", Permissions: []string{"message.text", "calendar.book"}},
		{AccountID: e.acctA, Fingerprint: "sha256:mine", Status: "pending_out"},
	} {
		if _, err := e.st.InsertContact(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	call := func(tool, fpr string) string {
		t.Helper()
		out, isErr := callJSON(t, cs, tool, map[string]any{"account_id": e.acctA, "contact_fpr": fpr})
		if isErr {
			t.Fatalf("%s %s: %s", tool, fpr, out)
		}
		return out
	}
	status := func(fpr string) string {
		c, err := e.st.GetContact(ctx, e.acctA, fpr)
		if err != nil {
			return "none"
		}
		return c.Status
	}

	// reject: a demotion, and the requester is told
	if out := call("reject_contact", "sha256:asker"); !strings.Contains(out, `"told":true`) || status("sha256:asker") != "blocked" {
		t.Fatalf("reject: %s, row %s", out, status("sha256:asker"))
	}
	if !slices.Equal(rejected, []string{"sha256:asker"}) {
		t.Fatalf("contact_rejected sent to %v", rejected)
	}
	// unblock of a rejected request forgets it
	if out := call("unblock_contact", "sha256:asker"); !strings.Contains(out, `"status":"none"`) || status("sha256:asker") != "none" {
		t.Fatalf("unblock of a rejected request: %s, row %s", out, status("sha256:asker"))
	}
	// block then unblock an active contact: back as it was, silently
	call("block_contact", "sha256:friend")
	if status("sha256:friend") != "blocked" {
		t.Fatal("block did not block")
	}
	if out := call("unblock_contact", "sha256:friend"); !strings.Contains(out, `"status":"active"`) {
		t.Fatalf("unblock of a blocked contact: %s", out)
	}
	if c, _ := e.st.GetContact(ctx, e.acctA, "sha256:friend"); c.Status != "active" || c.Preset != "friend" || len(c.Permissions) != 2 {
		t.Fatalf("unblocked contact is not the contact it was: %+v", c)
	}
	// unblock of something not blocked is a conflict, and nobody is unknown_contact
	if out, isErr := callJSON(t, cs, "unblock_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:friend"}); !isErr || !strings.Contains(out, "conflict") {
		t.Fatalf("unblock of an active contact: %s", out)
	}
	if out, isErr := callJSON(t, cs, "block_contact", map[string]any{"account_id": e.acctA, "contact_fpr": "sha256:nobody"}); !isErr || !strings.Contains(out, "unknown_contact") {
		t.Fatalf("block of nobody: %s", out)
	}
	// withdraw our own pending request: silent; remove an active contact: told
	call("remove_contact", "sha256:mine")
	call("remove_contact", "sha256:friend")
	if status("sha256:mine") != "none" || status("sha256:friend") != "none" {
		t.Fatal("remove left a row")
	}
	if !slices.Equal(removed, []string{"sha256:friend"}) {
		t.Fatalf("remove_contact was sent to %v; only the active contact is told", removed)
	}
	if len(unbounded) != 0 {
		t.Fatalf("courtesy calls made without a bound: %v", unbounded)
	}
}

// Invites: listed and revoked by the agent, and only the account's own. RevokeInvite took an id
// alone, so the portal could revoke any account's invite by its id — and so could this tool have.
func TestTheAgentListsAndRevokesOnlyItsAccountsInvites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, invA, err := e.deps.Contacts.CreateInvite(ctx, e.acctA, contacts.InviteOptions{Label: "work badge"})
	if err != nil {
		t.Fatal(err)
	}
	_, invB, err := e.deps.Contacts.CreateInvite(ctx, e.acctB, contacts.InviteOptions{Label: "home"})
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	out, isErr := callJSON(t, cs, "list_invites", map[string]any{"account_id": e.acctA})
	if isErr || !strings.Contains(out, invA.ID) || strings.Contains(out, invB.ID) || !strings.Contains(out, "work badge") {
		t.Fatalf("list_invites: %s", out)
	}
	// B's invite named under A: not found, and B's invite untouched
	if out, isErr := callJSON(t, cs, "revoke_invite", map[string]any{"account_id": e.acctA, "invite_id": invB.ID}); !isErr || !strings.Contains(out, "not_found") {
		t.Fatalf("revoking another account's invite: %s", out)
	}
	if l, _ := e.st.ListInvites(ctx, e.acctB); l[0].RevokedAt != 0 {
		t.Fatal("another account's invite was revoked")
	}
	if out, isErr := callJSON(t, cs, "revoke_invite", map[string]any{"account_id": e.acctA, "invite_id": invA.ID}); isErr {
		t.Fatalf("revoke: %s", out)
	}
	if l, _ := e.st.ListInvites(ctx, e.acctA); l[0].RevokedAt == 0 {
		t.Fatal("the invite was not revoked")
	}
	// a token narrowed to account A is denied account B outright
	narrow, _ := connect(t, e, auth.Identity{OwnerID: e.owner, AccountID: e.acctA}, nil)
	if out, isErr := callJSON(t, narrow, "revoke_invite", map[string]any{"account_id": e.acctB, "invite_id": invB.ID}); !isErr || !strings.Contains(out, "permission_denied") {
		t.Fatalf("a token narrowed to A revoking in B: %s", out)
	}
}

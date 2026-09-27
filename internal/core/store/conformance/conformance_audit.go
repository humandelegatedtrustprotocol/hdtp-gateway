package conformance

import (
	"context"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// auditPages is the suite for the account-scoped audit page.
func auditPages(t *testing.T, newStore Factory) {
	// The portal's audit page is account-scoped like every other page. Owners
	// are account-scoped too — memberships carry a role and asking for an
	// account you do not administer 404s — so a node-wide read handed one owner
	// another's contacts, bookings and message actions.
	t.Run("AuditPageScopesToAnAccountAndKeepsTheNodesOwnRows", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		mine, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
		theirs, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "theirs", DisplayName: "Theirs", Algo: "p256"})
		rows := []struct{ account, actor, action string }{
			{mine.ID, "contact-a", "send_message"},
			{theirs.ID, "contact-b", "book_slot"},
			{"", "owner", "portal_login"}, // the node's own: belongs to no account
		}
		for i, r := range rows {
			if err := s.InsertAuditEvent(ctx, int64(i+1), int64(1700000000+i), r.account,
				"contact", r.actor, r.action, "resource", "ok", "", "{}", "", "h"); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.ListAuditEventsPage(ctx, store.AuditPage{Account: mine.ID, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, r := range got {
			seen[r.Action] = true
		}
		if seen["book_slot"] {
			t.Error("another account's row was returned")
		}
		if !seen["send_message"] || !seen["portal_login"] {
			t.Errorf("scoping dropped rows it should keep: %+v", got)
		}
		// Newest first, and the actor filter still narrows within the scope.
		if len(got) > 1 && got[0].Seq < got[len(got)-1].Seq {
			t.Errorf("not newest-first: %+v", got)
		}
		byActor, err := s.ListAuditEventsPage(ctx, store.AuditPage{Actor: "contact-a", Account: mine.ID, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(byActor) != 1 || byActor[0].Action != "send_message" {
			t.Errorf("actor filter within an account: %+v", byActor)
		}
		// No account named: the whole trail, which is what the CLI reads.
		all, err := s.ListAuditEventsPage(ctx, store.AuditPage{Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 3 {
			t.Errorf("unscoped read returned %d of 3", len(all))
		}
	})
}

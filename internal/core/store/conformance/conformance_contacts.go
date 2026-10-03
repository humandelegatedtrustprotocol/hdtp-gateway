package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// contacts is the suite for contacts: the lifecycle, the guarded writes, pending requests and their expiry, invites, and what a contact granted us.
func contacts(t *testing.T, newStore Factory) {
	t.Run("ContactsLifecycle", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "c", DisplayName: "C", Algo: "p256"})
		c, err := s.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: "sha256:f1", SPKI: []byte{1, 2},
			Status: "pending_in", DisplayName: "Alina", Card: "BEGIN:VCARD...",
		})
		if err != nil {
			t.Fatal(err)
		}
		// No preset unless the owner picked one: the store must not invent a
		// label for a grant nobody has chosen yet.
		if c.TrustFlag != "messages_only" || c.Preset != "" || c.InviteID != "" {
			t.Fatalf("defaults wrong: %+v", c)
		}
		// The invite linkage survives a round-trip through both engines.
		if _, err := s.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: "sha256:via-invite", Status: "pending_in",
			DisplayName: "Guest", InviteID: "inv-123",
		}); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:via-invite"); got.InviteID != "inv-123" {
			t.Fatalf("invite id lost on Get: %+v", got)
		}
		if all, _ := s.ListContacts(ctx, a.ID); func() bool {
			for _, c := range all {
				if c.Fingerprint == "sha256:via-invite" && c.InviteID == "inv-123" {
					return false
				}
			}
			return true
		}() {
			t.Fatal("invite id lost on List")
		}
		// The lifecycle assertions below count rows; this probe leaves no trace.
		if err := s.DeleteContact(ctx, a.ID, "sha256:via-invite"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:f1", Status: "active"}); err == nil {
			t.Fatal("duplicate (account,fpr) accepted")
		}
		if _, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:f2", Status: "ghosted"}); err == nil {
			t.Fatal("invalid status accepted")
		}
		if err := s.UpdateContactStatus(ctx, a.ID, "sha256:f1", "active"); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateContactPermissions(ctx, a.ID, "sha256:f1", []string{"message.text", "calendar.book"}, "friend"); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetContact(ctx, a.ID, "sha256:f1")
		if got.Status != "active" || got.Preset != "friend" || len(got.Permissions) != 2 {
			t.Fatalf("updates lost: %+v", got)
		}
		all, _ := s.ListContacts(ctx, a.ID)
		if len(all) != 1 {
			t.Fatalf("list: %d", len(all))
		}
		// Removal is deletion, not demotion (SPEC §9.1 `active --> none`): the
		// pin goes with the row, so re-adding starts fresh.
		if err := s.DeleteContact(ctx, a.ID, "sha256:f1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetContact(ctx, a.ID, "sha256:f1"); err == nil {
			t.Fatal("deleted contact still readable")
		}
		if all, _ := s.ListContacts(ctx, a.ID); len(all) != 0 {
			t.Fatalf("list after delete: %d", len(all))
		}
		if err := s.DeleteContact(ctx, a.ID, "sha256:f1"); err == nil {
			t.Fatal("deleting a contact that is not there reported success")
		}
	})

	// Whether a relationship was ever active decides what an unblock does (SPEC §9.1): a contact
	// the owner blocked is restored, a rejected request is forgotten. The store is the one place
	// that knows every way a row becomes active, so it keeps the fact — and nothing clears it.
	t.Run("EverActiveIsSetByEveryActivationAndClearedByNone", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ea", DisplayName: "EA", Algo: "p256"})
		ever := func(fpr string) bool {
			t.Helper()
			c, err := s.GetContact(ctx, a.ID, fpr)
			if err != nil {
				t.Fatalf("%s: %v", fpr, err)
			}
			return c.EverActive
		}
		for _, st := range []string{"pending_in", "pending_out", "blocked"} {
			if _, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:" + st, Status: st}); err != nil {
				t.Fatal(err)
			}
			if ever("sha256:" + st) {
				t.Errorf("a row inserted %s says it was active", st)
			}
		}
		if _, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:auto", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		if !ever("sha256:auto") {
			t.Error("a row inserted active (an auto-accepted invite) does not say it was active")
		}
		// approve, then block: the block keeps the fact
		if err := s.UpdateContactStatus(ctx, a.ID, "sha256:pending_in", "active"); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateContactStatus(ctx, a.ID, "sha256:pending_in", "blocked"); err != nil {
			t.Fatal(err)
		}
		if !ever("sha256:pending_in") {
			t.Error("approve-then-block lost the fact that the row was active")
		}
		// a rejection is a move to blocked that was never active
		if err := s.UpdateContactStatus(ctx, a.ID, "sha256:blocked", "blocked"); err != nil {
			t.Fatal(err)
		}
		if ever("sha256:blocked") {
			t.Error("a move to blocked set the flag")
		}
		// the peer accepting our approach
		if err := s.SetContactAccepted(ctx, a.ID, "sha256:pending_out", "", nil, 1); err != nil {
			t.Fatal(err)
		}
		if !ever("sha256:pending_out") {
			t.Error("contact_accepted activated a row without recording it")
		}
		// an import knows only the status it carries
		if err := s.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:imp-active", Status: "active", TrustFlag: "messages_only", HandshakeDueAt: 1}); err != nil {
			t.Fatal(err)
		}
		if err := s.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:imp-blocked", Status: "blocked", TrustFlag: "messages_only", HandshakeDueAt: 1}); err != nil {
			t.Fatal(err)
		}
		if !ever("sha256:imp-active") || ever("sha256:imp-blocked") {
			t.Errorf("import: active=%v blocked=%v, want true and false", ever("sha256:imp-active"), ever("sha256:imp-blocked"))
		}
	})

	// A request still pending redeems one of the owner's invites: it takes the invite's status,
	// grant and linkage, and the pin the call proved. Only a pending_in row is written.
	t.Run("GuardedContactWritesMoveOnlyFromTheStatusRead", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "gw", DisplayName: "GW", Algo: "p256"})
		if _, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:gw", Status: "pending_in", SPKI: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.MoveContactStatus(ctx, a.ID, "sha256:gw", "active", "blocked"); err != nil || ok {
			t.Fatalf("a move from a status the row is not in: ok=%v err=%v", ok, err)
		}
		if ok, err := s.MoveContactStatus(ctx, a.ID, "sha256:gw", "pending_in", "active"); err != nil || !ok {
			t.Fatalf("the move from the status it is in: ok=%v err=%v", ok, err)
		}
		if c, _ := s.GetContact(ctx, a.ID, "sha256:gw"); c.Status != "active" || !c.EverActive {
			t.Fatalf("after the move: %+v", c)
		}
		if ok, err := s.DeleteContactInStatus(ctx, a.ID, "sha256:gw", "blocked"); err != nil || ok {
			t.Fatalf("a delete guarded by a status the row is not in: ok=%v err=%v", ok, err)
		}
		if ok, err := s.DeleteContactInStatus(ctx, a.ID, "sha256:gw", "active"); err != nil || !ok {
			t.Fatalf("the delete guarded by its status: ok=%v err=%v", ok, err)
		}
		if ok, err := s.MoveContactStatus(ctx, a.ID, "sha256:gw", "active", "blocked"); err != nil || ok {
			t.Fatalf("a move of a row that is gone: ok=%v err=%v", ok, err)
		}
	})

	t.Run("RedeemOverPendingContactWritesOnlyAPendingRequest", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ro", DisplayName: "RO", Algo: "p256"})
		if _, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:req", Status: "pending_in",
			SPKI: []byte{1}, Endpoint: "https://old.example", Leaf: []byte{2}, RootCert: []byte{3}, DisplayName: "Old"}); err != nil {
			t.Fatal(err)
		}
		ok, err := s.RedeemOverPendingContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:req", Status: "active",
			Preset: "friend", Permissions: []string{"message.text"}, InviteID: "inv-1", DisplayName: "New", Card: "CARD",
			SPKI: []byte{9}, Endpoint: "https://new.example", Leaf: []byte{8}})
		if err != nil || !ok {
			t.Fatalf("redeem over a pending request: ok=%v err=%v", ok, err)
		}
		got, _ := s.GetContact(ctx, a.ID, "sha256:req")
		if got.Status != "active" || !got.EverActive || got.Preset != "friend" || len(got.Permissions) != 1 ||
			got.InviteID != "inv-1" || got.Endpoint != "https://new.example" || string(got.Leaf) != string([]byte{8}) || got.Card != "CARD" {
			t.Fatalf("not written as redeemed: %+v", got)
		}
		if string(got.RootCert) != string([]byte{3}) {
			t.Errorf("a redemption that proved no root certificate dropped the one held: %v", got.RootCert)
		}
		// now active: a second redemption writes nothing
		ok, err = s.RedeemOverPendingContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:req", Status: "pending_in", Preset: "basic"})
		if err != nil || ok {
			t.Fatalf("an active row was overwritten by a redemption: ok=%v err=%v", ok, err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:req"); got.Status != "active" || got.Preset != "friend" {
			t.Fatalf("active row changed: %+v", got)
		}
	})

	// SPEC §9.1: an unanswered request expires. Only pending rows past the cutoff, of the account
	// named, go — and the sweep is told which, for the audit trail.
	t.Run("DeleteExpiredPendingContactsTakesOnlyOldRequests", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ex", DisplayName: "EX", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ex2", DisplayName: "EX2", Algo: "p256"})
		rows := []struct {
			acct, fpr, status string
			at                int64
		}{
			{a.ID, "sha256:old-in", "pending_in", 100},
			{a.ID, "sha256:old-out", "pending_out", 100},
			{a.ID, "sha256:old-active", "active", 100},
			{a.ID, "sha256:old-blocked", "blocked", 100},
			{a.ID, "sha256:young-in", "pending_in", 1000},
			{b.ID, "sha256:other-account", "pending_in", 100},
		}
		for _, r := range rows {
			if _, err := s.InsertContact(ctx, store.Contact{AccountID: r.acct, Fingerprint: r.fpr, Status: r.status, CreatedAt: r.at}); err != nil {
				t.Fatal(err)
			}
		}
		gone, err := s.DeleteExpiredPendingContacts(ctx, a.ID, 500)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{}
		for _, g := range gone {
			names[g.Fingerprint] = g.Status
		}
		if len(names) != 2 || names["sha256:old-in"] != "pending_in" || names["sha256:old-out"] != "pending_out" {
			t.Fatalf("expired %v, want exactly the two old requests", names)
		}
		for _, keep := range []string{"sha256:old-active", "sha256:old-blocked", "sha256:young-in"} {
			if _, err := s.GetContact(ctx, a.ID, keep); err != nil {
				t.Errorf("%s was removed by the expiry", keep)
			}
		}
		if _, err := s.GetContact(ctx, b.ID, "sha256:other-account"); err != nil {
			t.Error("another account's request was removed")
		}
	})

	// The request clock (migration 0043). A contact known for years that becomes a request today
	// (the handshake's fallback, HDTP §9.2) waits the whole window from today; a request that is
	// taken back returns to what it was, ever_active untouched; and an import names when its
	// handshake became owed.
	t.Run("TheExpiryWindowRunsFromTheRequest", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "rq", DisplayName: "RQ", Algo: "p256"})
		if err := s.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:old-friend", Status: "active", TrustFlag: "messages_only", CreatedAt: 100}); err == nil {
			t.Fatal("an import without the time its handshake became owed was written")
		}
		if err := s.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:old-friend", Status: "active", TrustFlag: "messages_only", CreatedAt: 100, HandshakeDueAt: 900}); err != nil {
			t.Fatal(err)
		}
		if c, _ := s.GetContact(ctx, a.ID, "sha256:old-friend"); !c.HandshakeDue || c.HandshakeDueAt != 900 || c.RequestedAt != 0 {
			t.Fatalf("imported: due=%v at=%d requested=%d", c.HandshakeDue, c.HandshakeDueAt, c.RequestedAt)
		}
		if ok, err := s.MarkContactRequested(ctx, a.ID, "sha256:old-friend", "blocked", 1000); err != nil || ok {
			t.Fatalf("a mark from a status the row is not in: %v %v", ok, err)
		}
		if ok, err := s.MarkContactRequested(ctx, a.ID, "sha256:old-friend", "active", 1000); err != nil || !ok {
			t.Fatalf("mark: %v %v", ok, err)
		}
		if gone, err := s.DeleteExpiredPendingContacts(ctx, a.ID, 500); err != nil || len(gone) != 0 {
			t.Fatalf("a request made at 1000 expired at a cutoff of 500 because the contact dates from 100: %v %v", gone, err)
		}
		if ok, err := s.TakeBackContactRequest(ctx, a.ID, "sha256:old-friend", "active", 0, 999); err != nil || ok {
			t.Fatalf("a take-back of another mark: %v %v", ok, err)
		}
		if ok, err := s.TakeBackContactRequest(ctx, a.ID, "sha256:old-friend", "active", 0, 1000); err != nil || !ok {
			t.Fatalf("take back: %v %v", ok, err)
		}
		if c, _ := s.GetContact(ctx, a.ID, "sha256:old-friend"); c.Status != "active" || c.RequestedAt != 0 || !c.EverActive {
			t.Fatalf("taken back: %s requested=%d ever=%v", c.Status, c.RequestedAt, c.EverActive)
		}
		if _, err := s.MarkContactRequested(ctx, a.ID, "sha256:old-friend", "active", 1000); err != nil {
			t.Fatal(err)
		}
		if gone, err := s.DeleteExpiredPendingContacts(ctx, a.ID, 1001); err != nil || len(gone) != 1 {
			t.Fatalf("the request still expires once the window from it has run: %v %v", gone, err)
		}
	})

	// An invite id is not an authority: revoking one names the account it belongs to, and an id
	// of another account's invite is not found there.
	t.Run("RevokeInviteIsScopedToItsAccount", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ri", DisplayName: "RI", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ri2", DisplayName: "RI2", Algo: "p256"})
		inv, err := s.InsertInvite(ctx, store.Invite{AccountID: a.ID, TokenHash: []byte("h-ri"), ExpiresAt: 1 << 40, MaxUses: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeInvite(ctx, b.ID, inv.ID, 5); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another account's revocation answered %v, want ErrNotFound", err)
		}
		list, _ := s.ListInvites(ctx, a.ID)
		if len(list) != 1 || list[0].RevokedAt != 0 {
			t.Fatalf("the invite changed: %+v", list)
		}
		if err := s.RevokeInvite(ctx, a.ID, inv.ID, 5); err != nil {
			t.Fatalf("its own account could not revoke it: %v", err)
		}
	})

	// `their_permissions` is what a contact granted US (HDTP §6.2) — the answer to
	// "what may my agent call on them", and the reason ContactAccepted records it
	// at all. The column exists, SetContactAccepted writes it, and until now every
	// read dropped it: the SELECTs did not fetch the column and the row struct had
	// no field for it. So the value was write-only, and the probing it was added
	// to remove was still the only way to find out.
	t.Run("TheirPermissionsSurviveAWriteAndRead", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "tp", DisplayName: "TP", Algo: "p256"})
		if _, err := s.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: "sha256:tp1", SPKI: []byte{9},
			Status: "pending_out", DisplayName: "Peer", Card: "BEGIN:VCARD...",
		}); err != nil {
			t.Fatal(err)
		}
		granted := []string{"message.text", "calendar.book"}
		if err := s.SetContactAccepted(ctx, a.ID, "sha256:tp1", "BEGIN:VCARD...", granted, 1756000000); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetContact(ctx, a.ID, "sha256:tp1")
		if err != nil {
			t.Fatal(err)
		}
		if len(got.TheirPermissions) != 2 {
			t.Errorf("GetContact dropped what the peer granted us: %+v", got.TheirPermissions)
		}
		// and it must survive the list path too, which is what the portal renders
		all, err := s.ListContacts(ctx, a.ID)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v (%d rows)", err, len(all))
		}
		if len(all[0].TheirPermissions) != 2 {
			t.Errorf("ListContacts dropped it: %+v", all[0].TheirPermissions)
		}
		// what WE grant them is a different field and must not be touched by this
		if len(got.Permissions) != 0 {
			t.Errorf("accepting a peer granted them %v on our node", got.Permissions)
		}
	})
}

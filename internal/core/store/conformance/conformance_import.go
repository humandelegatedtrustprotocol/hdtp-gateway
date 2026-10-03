package conformance

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// importAndMove is the suite for an import lands whole or not at all, a move campaign is resumable, and an imported contact keeps what its export carried.
func importAndMove(t *testing.T, newStore Factory) {
	// An import (SPEC sec. 3.10) is one transaction: an identity, its contacts and its
	// conversations all land, or none of them does. Half an identity is worse than none - a
	// person's contacts without their conversations, under a name the node would then refuse to
	// import again. Both engines have to mean the same thing by it.
	t.Run("AtomicallyLandsEverythingOrNothing", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		boom := errors.New("the file ended here")
		err := s.Atomically(ctx, func(tx store.Store) error {
			a, err := tx.CreateAccount(ctx, store.CreateAccountParams{Slug: "half", DisplayName: "Half", Algo: "p256"})
			if err != nil {
				return err
			}
			if err := tx.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:c1", Status: "active", TrustFlag: "messages_only", CreatedAt: 5, HandshakeDueAt: 1}); err != nil {
				return err
			}
			// Visible INSIDE the transaction, or the importer could not check for a collision.
			if list, _ := tx.ListContacts(ctx, a.ID); len(list) != 1 {
				t.Fatalf("a write is not visible to the transaction that made it: %d contacts", len(list))
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("the callback's error must come back as it is: %v", err)
		}
		if _, err := s.GetAccountBySlug(ctx, "half"); err == nil {
			t.Fatal("a rolled-back import left its account behind")
		}

		var id string
		if err := s.Atomically(ctx, func(tx store.Store) error {
			a, err := tx.CreateAccount(ctx, store.CreateAccountParams{Slug: "whole", DisplayName: "Whole", Algo: "p256"})
			id = a.ID
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got, err := s.GetAccountBySlug(ctx, "whole"); err != nil || got.ID != id {
			t.Fatalf("a committed import is not there: %v", err)
		}
	})

	// A move campaign's progress (HDTP §5.3, §9) is what "re-run to resume" reads: one row per
	// contact, replaced as the walk retries, matched on the leaf being announced. The campaign's
	// own tests use SQLite, so this case is where Postgres runs either statement.
	t.Run("MoveFanoutIsOneRowPerContactAndResumable", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		mine, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "mover", DisplayName: "Mover", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		other, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "bystander", DisplayName: "Bystander", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		put := func(f store.MoveFanout) {
			t.Helper()
			if err := s.UpsertMoveFanout(ctx, f); err != nil {
				t.Fatalf("recording %+v: %v", f, err)
			}
		}
		put(store.MoveFanout{AccountID: mine.ID, ContactFpr: "sha256:b", LeafKid: "sha256:leaf1", Status: "pending", Attempts: 1, LastError: "unreachable", UpdatedAt: 10})
		put(store.MoveFanout{AccountID: mine.ID, ContactFpr: "sha256:a", LeafKid: "sha256:leaf1", Status: "done", Attempts: 1, UpdatedAt: 11})
		put(store.MoveFanout{AccountID: other.ID, ContactFpr: "sha256:b", LeafKid: "sha256:leafX", Status: "pending", Attempts: 4, UpdatedAt: 12})
		// The retry reaches them: the same contact is the same row, replaced whole.
		put(store.MoveFanout{AccountID: mine.ID, ContactFpr: "sha256:b", LeafKid: "sha256:leaf1", Status: "done", Attempts: 2, UpdatedAt: 20})

		rows, err := s.ListMoveFanout(ctx, mine.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := []store.MoveFanout{
			{AccountID: mine.ID, ContactFpr: "sha256:a", LeafKid: "sha256:leaf1", Status: "done", Attempts: 1, UpdatedAt: 11},
			{AccountID: mine.ID, ContactFpr: "sha256:b", LeafKid: "sha256:leaf1", Status: "done", Attempts: 2, UpdatedAt: 20},
		}
		if !reflect.DeepEqual(rows, want) {
			t.Fatalf("one account's progress, by contact, each contact once:\n got  %+v\n want %+v", rows, want)
		}
		// A second move is a second campaign: the row now names the newer leaf, which is what
		// the walk compares before it decides a contact has already been told.
		put(store.MoveFanout{AccountID: mine.ID, ContactFpr: "sha256:a", LeafKid: "sha256:leaf2", Status: "pending", Attempts: 1, UpdatedAt: 30})
		rows, _ = s.ListMoveFanout(ctx, mine.ID)
		if len(rows) != 2 || rows[0].LeafKid != "sha256:leaf2" || rows[0].Status != "pending" {
			t.Fatalf("a newer campaign must replace the contact's row: %+v", rows)
		}
		// And another account's progress is its own, however alike the contact looks.
		if theirs, _ := s.ListMoveFanout(ctx, other.ID); len(theirs) != 1 || theirs[0].Attempts != 4 {
			t.Fatalf("another account's progress was touched: %+v", theirs)
		}
	})

	// A contact arriving in an export carries every column an export carries - the owner's name
	// for them, the trust flag, what they granted us - and none it does not.
	t.Run("ImportContactWritesWhatAnExportCarries", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		in := store.Contact{
			AccountID: a.ID, Fingerprint: "sha256:root", SPKI: []byte("spki"), Status: "blocked", Preset: "close",
			Permissions: []string{"message.send"}, TheirPermissions: []string{"calendar.read"}, TrustFlag: "may_instruct",
			DisplayName: "Bharat", Petname: "B from the conference", Card: "BEGIN:VCARD", CreatedAt: 11, PinnedAt: 12,
			Endpoint: "https://b.example/mcp", Leaf: []byte("leaf"), RootCert: []byte("root"), HandshakeDueAt: 13,
		}
		if err := s.ImportContact(ctx, in); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetContact(ctx, a.ID, "sha256:root")
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "blocked" || got.Petname != in.Petname || got.TrustFlag != "may_instruct" ||
			len(got.TheirPermissions) != 1 || got.TheirPermissions[0] != "calendar.read" ||
			len(got.Permissions) != 1 || got.Preset != "close" || got.PinnedAt != 12 || got.CreatedAt != 11 ||
			got.Endpoint != in.Endpoint || string(got.Leaf) != "leaf" || string(got.SPKI) != "spki" || string(got.RootCert) != "root" {
			t.Fatalf("an imported contact lost something on the way in: %+v", got)
		}
		// Host state does not travel: no invite, and nothing about which of OUR leaves they saw.
		if got.InviteID != "" || got.ChainSentKid != "" {
			t.Fatalf("an imported contact arrived with the old host's state: invite=%q chain_sent_kid=%q", got.InviteID, got.ChainSentKid)
		}
		// It is owed this host's handshake (HDTP §9.2), until the campaign clears the mark; a
		// contact made here any other way is owed nothing.
		if !got.HandshakeDue {
			t.Fatal("an imported contact arrived without the mark that it is owed a handshake")
		}
		if err := s.ClearContactHandshake(ctx, a.ID, "sha256:root"); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:root"); got.HandshakeDue {
			t.Fatal("clearing the handshake mark left it set")
		}
		if err := s.ClearContactHandshake(ctx, a.ID, "sha256:nobody"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("clearing the mark of a contact that is not there: %v, want ErrNotFound", err)
		}
		made, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:made-here", SPKI: []byte("s"), Status: "active"})
		if err != nil {
			t.Fatal(err)
		}
		if made.HandshakeDue {
			t.Fatal("a contact made on this host is marked as owed an import's handshake")
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:made-here"); got.HandshakeDue {
			t.Fatal("a contact made on this host reads back as owed an import's handshake")
		}
	})
}

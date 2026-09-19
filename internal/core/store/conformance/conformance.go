// Package conformance is the single test suite every Store engine must pass
// (SPEC §11.1): the engines cannot drift apart because they are judged by the
// same tests. Engine packages call Run with a fresh-store factory.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

// Migratable is what the suite needs beyond store.Store: down-migration for the
// up/down/up cleanliness check.
type Migratable interface {
	store.Store
	MigrateDown(ctx context.Context) error
}

// Factory returns a NEW, empty, unmigrated store. The suite migrates it and the
// factory's cleanup must drop whatever it created.
type Factory func(t *testing.T) Migratable

func Run(t *testing.T, newStore Factory) {
	t.Run("MigrateUpDownUp", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("up: %v", err)
		}
		if err := s.MigrateDown(ctx); err != nil {
			t.Fatalf("down: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("re-up: %v", err)
		}
	})

	// MigrateUpDownUp above runs against an EMPTY database, so every
	// down-migration branch that handles DATA is never executed — and that is
	// the half that can fail. 0021 narrows the messages uniqueness key on the
	// way down and must first drop rows that are legal under the wide key and
	// collide under the narrow one; 0024 must rewrite a status the older CHECK
	// constraint does not allow. Both are exactly the shape that works on an
	// empty table and destroys, or refuses, a populated one.
	t.Run("MigrateDownAndUpWithDataPresent", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "roll", DisplayName: "Roll", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		// The two rows a naive rollback trips over: a msg_id used in BOTH
		// directions (legal now, a duplicate under the older key), and a status
		// the older CHECK constraint does not know.
		rows := []store.Message{
			{ID: "r1", MsgID: "shared", Direction: "in", Status: "delivered"},
			{ID: "r2", MsgID: "shared", Direction: "out", Status: "queued_at_relay"},
			{ID: "r3", MsgID: "solo", Direction: "out", Status: "pending"},
		}
		for _, m := range rows {
			m.AccountID, m.ContactFpr, m.ThreadID = a.ID, "sha256:p", "t1"
			m.Sender, m.Kind, m.Body, m.CreatedAt = "human", "text", m.ID, 100
			if err := s.InsertMessage(ctx, m); err != nil {
				t.Fatalf("seeding %s: %v", m.ID, err)
			}
		}

		// A full rollback runs every down-migration in reverse WITH these rows
		// present, then drops the tables — so what this pins is that the
		// down-path does not FAIL on real data. 0021 must dedupe the shared
		// msg_id before it can narrow the key (the rebuild's INSERT would hit
		// the UNIQUE constraint otherwise), and 0024 must rewrite
		// queued_at_relay before it can reinstate the older CHECK.
		//
		// It cannot assert the rows survive: DownTo(0) drops the schema by
		// design. That is what a full rollback means, and a test claiming
		// otherwise would be pinning a promise the tool does not make.
		if err := s.MigrateDown(ctx); err != nil {
			t.Fatalf("rolling back a populated database failed — a down-migration that "+
				"errors here leaves an operator half-migrated: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("re-applying after a populated rollback failed: %v", err)
		}

		// And the schema that comes back is the current one: a msg_id may be
		// used once in each direction.
		a2, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "roll2", DisplayName: "Roll2", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t2", AccountID: a2.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		for i, dir := range []string{"in", "out"} {
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("post%d", i), AccountID: a2.ID, ContactFpr: "sha256:p",
				MsgID: "shared", ThreadID: "t2", Direction: dir, Sender: "human",
				Kind: "text", Body: dir, Status: "delivered", CreatedAt: 100,
			}); err != nil {
				t.Fatalf("after a rollback and re-up the %s direction was refused: %v", dir, err)
			}
		}
	})

	t.Run("OwnerCRUD", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, err := s.CreateOwnerWithID(ctx, "", "Sumit")
		if err != nil {
			t.Fatal(err)
		}
		if o.ID == "" || o.DisplayName != "Sumit" {
			t.Fatalf("bad owner: %+v", o)
		}
		got, err := s.GetOwner(ctx, o.ID)
		if err != nil || got.DisplayName != "Sumit" {
			t.Fatalf("get: %v %+v", err, got)
		}
		all, err := s.ListOwners(ctx)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v %d", err, len(all))
		}
		if err := s.DeleteOwner(ctx, o.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetOwner(ctx, o.ID); err == nil {
			t.Fatal("deleted owner still readable")
		}
	})

	t.Run("AccountCRUDAndConstraints", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "work", DisplayName: "Work", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Seal != "required" || a.Status != "active" {
			t.Fatalf("defaults wrong: %+v", a)
		}
		if _, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "work", DisplayName: "Dup", Algo: "p256"}); err == nil {
			t.Fatal("duplicate slug accepted")
		}
		got, err := s.GetAccountBySlug(ctx, "work")
		if err != nil || got.ID != a.ID {
			t.Fatalf("get by slug: %v", err)
		}
		if _, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "x", DisplayName: "X", Algo: "rsa"}); err == nil {
			t.Fatal("invalid algo accepted")
		}
	})

	t.Run("AccountKeyBindsOnce", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "k", DisplayName: "K", Algo: "p256"})
		if err := s.SetAccountKey(ctx, a.ID, "sha256:abc", []byte{9}); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetAccountBySlug(ctx, "k")
		if got.Fingerprint != "sha256:abc" {
			t.Fatalf("fingerprint not stored: %+v", got)
		}
		if err := s.SetAccountKey(ctx, a.ID, "sha256:other", []byte{1}); err == nil {
			t.Fatal("re-keying via SetAccountKey must be refused")
		}
	})

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

	// `their_permissions` is what a contact granted US (PACT §6.2) — the answer to
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

	// The petname is the OWNER's name for a contact -- optional, local, and the
	// only name no peer can influence. display_name is the contact's own claim,
	// so several contacts may honestly share one; this is the field that settles
	// which is which.
	// WebAuthn binds a credential to a user handle when the authenticator makes
	// it, and replays that handle on every later login. So a first passkey has to
	// name the owner id BEFORE the owner row exists — which is what this method
	// is for, and why an owner id minted independently made every first passkey
	// unusable for login.
	t.Run("AnOwnerCanBeCreatedUnderAChosenID", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		const chosen = "0123456789abcdef0123456789abcdef"
		o, err := s.CreateOwnerWithID(ctx, chosen, "Chosen")
		if err != nil {
			t.Fatal(err)
		}
		if o.ID != chosen {
			t.Fatalf("owner id is %q, want the chosen %q", o.ID, chosen)
		}
		back, err := s.GetOwner(ctx, chosen)
		if err != nil {
			t.Fatalf("an owner created under a chosen id cannot be read back: %v", err)
		}
		if back.DisplayName != "Chosen" {
			t.Errorf("display name lost: %q", back.DisplayName)
		}
		// An empty id still yields a usable owner rather than an empty-string row.
		auto, err := s.CreateOwnerWithID(ctx, "", "Auto")
		if err != nil {
			t.Fatal(err)
		}
		if auto.ID == "" {
			t.Error("an empty id produced an owner with no id")
		}
	})

	t.Run("PetnameIsLocalAndSurvivesAMove", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "pn", DisplayName: "PN", Algo: "p256"})
		if _, err := s.InsertContact(ctx, store.Contact{
			AccountID: a.ID, Fingerprint: "sha256:pn1", SPKI: []byte{7},
			Status: "active", DisplayName: "Alice", Card: "BEGIN:VCARD...",
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetContactPetname(ctx, a.ID, "sha256:pn1", "Alice from work"); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetContact(ctx, a.ID, "sha256:pn1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Petname != "Alice from work" {
			t.Errorf("GetContact dropped the petname: %q", got.Petname)
		}
		if got.DisplayName != "Alice" {
			t.Errorf("naming a contact overwrote the name THEY supplied: %q", got.DisplayName)
		}
		all, err := s.ListContacts(ctx, a.ID)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v (%d rows)", err, len(all))
		}
		if all[0].Petname != "Alice from work" {
			t.Errorf("ListContacts dropped the petname, which is the path the portal renders: %q",
				all[0].Petname)
		}

		// A move re-pins the contact at a new address. The petname is the owner's,
		// not the contact's, so nothing a peer does must discard it -- that would
		// hand a peer a way to shed a name the owner gave them. It used to be proved
		// over a 1.x rotation, which re-pinned under a NEW fingerprint; a root never
		// moves, so the re-pin that exists now keeps the fingerprint and changes the
		// address.
		if err := s.RepinContactAddress(ctx, a.ID, "sha256:pn1", "https://moved.example/mcp", []byte("leaf"), []byte{8}, 1756000001); err != nil {
			t.Fatal(err)
		}
		after, err := s.GetContact(ctx, a.ID, "sha256:pn1")
		if err != nil {
			t.Fatal(err)
		}
		if after.Petname != "Alice from work" {
			t.Errorf("a move dropped the owner's own name for the contact: %q", after.Petname)
		}

		// Clearing is how the owner goes back to the contact's own name.
		if err := s.SetContactPetname(ctx, a.ID, "sha256:pn1", ""); err != nil {
			t.Fatal(err)
		}
		cleared, err := s.GetContact(ctx, a.ID, "sha256:pn1")
		if err != nil {
			t.Fatal(err)
		}
		if cleared.Petname != "" {
			t.Errorf("petname could not be cleared: %q", cleared.Petname)
		}
	})

	// PACT 2.0 (migration 0027): the root beside the account, the leaf ledger,
	// 2.0 pins that move without the root moving, and the §5.3 side tables.
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
			if err := tx.ImportContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:c1", Status: "active", TrustFlag: "messages_only", CreatedAt: 5}); err != nil {
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

	// A move campaign's progress (PACT §5.3, §9) is what "re-run to resume" reads: one row per
	// contact, replaced as the walk retries, matched on the leaf being announced. No case here
	// touched the table until it was renamed (0036), so on Postgres nothing had ever run either
	// statement — the campaign's tests use SQLite, and a migration that runs proves only that.
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
			Endpoint: "https://b.example/mcp", Leaf: []byte("leaf"), RootCert: []byte("root"),
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
	})

	t.Run("Pact20StateRoundTrips", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "p20", DisplayName: "P", Algo: "ed25519"})
		// A new account holds a key and no leaf: it is protocol 1 in the row until
		// `install-leaf` writes 2, and it serves nothing until then.
		if a.AcceptNewHosts != "auto" {
			t.Fatalf("account defaults wrong: %+v", a)
		}
		// An account with no key reads as NO KEY, in both engines, and not as an
		// error: that is the shape a data-only archive arrives in, and the node,
		// `csr -purpose signup` and `install-leaf` all decide from an empty slice
		// (PACT §9). An error here made every one of those branches unreachable.
		if k, kerr := s.GetAccountSealedKey(ctx, a.ID); kerr != nil || len(k) != 0 {
			t.Fatalf("an account with no key must read as empty, not as an error: %q %v", k, kerr)
		}
		if err := s.SetAccountKey(ctx, a.ID, "sha256:leaf1", []byte("sealed1")); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAccountRoot(ctx, a.ID, "sha256:root", []byte("root-der")); err != nil {
			t.Fatal(err)
		}
		if err := s.SetAccountHostPolicy(ctx, a.ID, "ask"); err != nil {
			t.Fatal(err)
		}
		// A leaf install moves the key SetAccountKey bound once.
		if err := s.SetAccountLeafKey(ctx, a.ID, "sha256:leaf2", []byte("sealed2"), "p256"); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetAccountByID(ctx, a.ID)
		if !got.HasRoot() || got.RootFingerprint != "sha256:root" || string(got.RootCert) != "root-der" || got.AcceptNewHosts != "ask" || got.Fingerprint != "sha256:leaf2" || got.Algo != "p256" {
			t.Fatalf("2.0 account fields lost: %+v", got)
		}
		if k, _ := s.GetAccountSealedKey(ctx, a.ID); string(k) != "sealed2" {
			t.Fatalf("leaf key not moved: %q", k)
		}
		for _, l := range []store.Leaf{
			{AccountID: a.ID, Kid: "sha256:leaf1", Leaf: []byte("l1"), KeySealed: []byte("k1"), NotBefore: 1, NotAfter: 10, State: "superseded", Endpoint: "https://a.example/mcp"},
			{AccountID: a.ID, Kid: "sha256:leaf2", Leaf: []byte("l2"), KeySealed: []byte("k2"), NotBefore: 2, NotAfter: 20, State: "current", Endpoint: "https://a.example/mcp"},
			{AccountID: a.ID, Kid: "sha256:leaf3", State: "pending", Endpoint: "https://b.example/mcp", KeySealed: []byte("k3")},
		} {
			if err := s.InsertLeaf(ctx, l); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:leaf3", State: "current", Endpoint: "x"}); err == nil {
			t.Fatal("duplicate (account, kid) accepted")
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:bad", State: "live", Endpoint: "x"}); err == nil {
			t.Fatal("invalid leaf state accepted")
		}
		if err := s.RetireLeafKey(ctx, a.ID, "sha256:leaf1"); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:leaf3", Leaf: []byte("l3"), NotBefore: 3, NotAfter: 30, State: "current", Endpoint: "https://b.example/mcp"}); err != nil {
			t.Fatal(err)
		}
		leaves, _ := s.ListLeaves(ctx, a.ID)
		if len(leaves) != 3 {
			t.Fatalf("leaves: %d", len(leaves))
		}
		byKid := map[string]store.Leaf{}
		for _, l := range leaves {
			byKid[l.Kid] = l
		}
		if l := byKid["sha256:leaf1"]; l.State != "former" || l.KeySealed != nil {
			t.Fatalf("retire did not destroy the key: %+v", l)
		}
		if l := byKid["sha256:leaf3"]; l.State != "current" || string(l.Leaf) != "l3" || l.NotAfter != 30 || string(l.KeySealed) != "k3" {
			t.Fatalf("update lost: %+v", l)
		}
		// The account's own copy of its current leaf's key goes the same way, and the fingerprint
		// stays: it is how pins, routes and audit rows name the account.
		if err := s.SetAccountLeafKey(ctx, a.ID, "sha256:leaf3", []byte("k3"), "p256"); err != nil {
			t.Fatal(err)
		}
		if err := s.ClearAccountKey(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		if k, err := s.GetAccountSealedKey(ctx, a.ID); err != nil || len(k) != 0 {
			t.Fatalf("the account's key survived being cleared: %d bytes, %v", len(k), err)
		}
		if got, _ := s.GetAccountByID(ctx, a.ID); got.Fingerprint != "sha256:leaf3" {
			t.Fatalf("clearing the key must keep the fingerprint: %q", got.Fingerprint)
		}
		if err := s.ClearAccountKey(ctx, "no-such-account"); err == nil {
			t.Fatal("clearing an unknown account's key reported success")
		}
		// The sibling kids: what another identity on this node holds. One inbound
		// envelope asks for this to tell a kid held elsewhere on the node from one
		// this endpoint never held (PACT §13.3, §14.4), so it must never answer
		// with the asking account's own kids, and must see every other account's.
		other, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "sibling", DisplayName: "Sibling", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.InsertLeaf(ctx, store.Leaf{AccountID: other.ID, Kid: "sha256:sibling-leaf", State: "current", Endpoint: "https://s.example/mcp"}); err != nil {
			t.Fatal(err)
		}
		mine, err := s.ListKidsExcept(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) != 1 || mine[0] != "sha256:sibling-leaf" {
			t.Fatalf("the siblings' kids and nothing of our own: %v", mine)
		}
		theirs, err := s.ListKidsExcept(ctx, other.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(theirs) != 3 {
			t.Fatalf("every kid of the other account: %v", theirs)
		}
		if n, _ := s.DeleteLeavesByState(ctx, a.ID, "former"); n != 1 {
			t.Fatalf("delete former: %d", n)
		}
		// A 2.0 pin: the fingerprint column is the root and never moves; the
		// endpoint, the leaf and its key do (PACT §14.3, §5.3).
		c, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:peer-root", SPKI: []byte{1}, Status: "active",
			Endpoint: "https://p.example/mcp", Leaf: []byte("pl1"), ChainSentKid: "sha256:leaf2"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Endpoint != "https://p.example/mcp" || string(c.Leaf) != "pl1" || c.ChainSentKid != "sha256:leaf2" {
			t.Fatalf("2.0 pin fields lost: %+v", c)
		}
		// The ROOT's certificate is kept beside the pin (migration 0029): the chain
		// travels once, so a host that keeps only the fingerprint cannot prove a
		// stored leaf afterwards, here or in an archive taken here. It fills in when
		// a chain arrives and is never overwritten - a pin's root cannot change.
		if len(c.RootCert) != 0 {
			t.Fatalf("a pin made with no root certificate must read back empty: %q", c.RootCert)
		}
		if err := s.SetContactRootCert(ctx, a.ID, "sha256:peer-root", []byte("peer-root-der")); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:peer-root"); string(got.RootCert) != "peer-root-der" {
			t.Fatalf("the root certificate did not persist: %q", got.RootCert)
		}
		if err := s.SetContactRootCert(ctx, a.ID, "sha256:peer-root", []byte("someone-elses-der")); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.GetContact(ctx, a.ID, "sha256:peer-root"); string(got.RootCert) != "peer-root-der" {
			t.Fatalf("a stored root certificate was overwritten: %q", got.RootCert)
		}
		if withCert, err := s.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: "sha256:pinned-with-cert", SPKI: []byte{3}, Status: "active",
			Endpoint: "https://w.example/mcp", Leaf: []byte("wl1"), RootCert: []byte("w-root-der")}); err != nil || string(withCert.RootCert) != "w-root-der" {
			t.Fatalf("a pin made WITH a root certificate lost it: %+v %v", withCert, err)
		}
		if err := s.RepinContactAddress(ctx, a.ID, "sha256:peer-root", "https://q.example/mcp", []byte("pl2"), []byte{9}, 77); err != nil {
			t.Fatal(err)
		}
		// A move does not touch the root or its certificate.
		if got, _ := s.GetContact(ctx, a.ID, "sha256:peer-root"); string(got.RootCert) != "peer-root-der" {
			t.Fatalf("a move lost the root certificate: %q", got.RootCert)
		}
		if err := s.ClearChainSentKids(ctx, a.ID); err != nil {
			t.Fatal(err)
		}
		c, _ = s.GetContact(ctx, a.ID, "sha256:peer-root")
		if c.Endpoint != "https://q.example/mcp" || string(c.Leaf) != "pl2" || c.SPKI[0] != 9 || c.PinnedAt != 77 || c.ChainSentKid != "" {
			t.Fatalf("repin lost: %+v", c)
		}
		if err := s.SetContactChainSentKid(ctx, a.ID, "sha256:peer-root", "sha256:leaf3"); err != nil {
			t.Fatal(err)
		}
		if err := s.RepinContactAddress(ctx, a.ID, "sha256:nobody", "x", nil, nil, 1); err == nil {
			t.Fatal("repin of a missing contact reported success")
		}
		// The §5.3 side tables.
		if err := s.UpsertTombstone(ctx, store.Tombstone{AccountID: a.ID, Root: "sha256:gone", Leaf: []byte("gl"), At: 5}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertTombstone(ctx, store.Tombstone{AccountID: a.ID, Root: "sha256:gone", Leaf: []byte("gl2"), At: 6}); err != nil {
			t.Fatal(err)
		}
		if ts, _ := s.ListTombstones(ctx, a.ID); len(ts) != 1 || string(ts[0].Leaf) != "gl2" || ts[0].At != 6 {
			t.Fatalf("tombstone upsert: %+v", ts)
		}
		if err := s.DeleteTombstone(ctx, a.ID, "sha256:gone"); err != nil {
			t.Fatal(err)
		}
		if ts, _ := s.ListTombstones(ctx, a.ID); len(ts) != 0 {
			t.Fatalf("tombstone not deleted: %+v", ts)
		}
		for _, f := range []store.FormerEndpoint{{AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://p.example/mcp", At: 1}, {AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://p.example/mcp", At: 2}} {
			if err := s.InsertFormerEndpoint(ctx, f); err != nil {
				t.Fatal(err)
			}
		}
		if fs, _ := s.ListFormerEndpoints(ctx, a.ID); len(fs) != 2 {
			t.Fatalf("former endpoints: %+v", fs)
		}
		if err := s.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://r.example/mcp", Leaf: []byte("pl3"), Why: "ask", At: 9, RootCert: []byte("root-der")}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertPendingAddress(ctx, store.PendingAddress{AccountID: a.ID, Root: "sha256:peer-root", Endpoint: "https://s.example/mcp", Leaf: []byte("pl4"), Why: "returned after removal", At: 10}); err != nil {
			t.Fatal(err)
		}
		if p, err := s.GetPendingAddress(ctx, a.ID, "sha256:peer-root"); err != nil || p.Endpoint != "https://s.example/mcp" || p.Why != "returned after removal" {
			t.Fatalf("pending upsert: %+v %v", p, err)
		}
		// A pending address keeps the root's certificate too: the owner may sit on the
		// decision for days, and the chain that carried it does not come back.
		if ps, _ := s.ListPendingAddresses(ctx, a.ID); len(ps) != 1 || string(ps[0].RootCert) != "root-der" {
			t.Fatalf("pending address lost its root certificate: %+v", ps)
		}
		if ps, _ := s.ListPendingAddresses(ctx, a.ID); len(ps) != 1 {
			t.Fatalf("pending list: %+v", ps)
		}
		if err := s.DeletePendingAddress(ctx, a.ID, "sha256:peer-root"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetPendingAddress(ctx, a.ID, "sha256:peer-root"); err == nil {
			t.Fatal("pending address still readable after delete")
		}
	})

	t.Run("RetentionPrimitives", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "ret", DisplayName: "Ret", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		for i, ts := range []int64{100, 500} {
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("m%d", i), AccountID: a.ID, ContactFpr: "sha256:p",
				MsgID: fmt.Sprintf("msg%d", i), ThreadID: "t1", Direction: "in",
				Sender: "human", Kind: "text", Body: "hi", Status: "delivered", CreatedAt: ts,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: "deadbeef", Size: 10, CreatedAt: 100}); err != nil {
			t.Fatal(err)
		}
		// SumBlobBytes drives the media quota, and on Postgres SUM(bigint) is
		// NUMERIC — a scan that missed the type silently answered 0 and the
		// quota never bit. This is what pins the conversion on both engines.
		if used, err := s.SumBlobBytes(ctx, a.ID); err != nil || used != 10 {
			t.Fatalf("SumBlobBytes = %d, %v; want 10", used, err)
		}
		// only what is older than the cutoff goes
		n, err := s.DeleteMessagesBefore(ctx, a.ID, 300)
		if err != nil || n != 1 {
			t.Fatalf("DeleteMessagesBefore: %d %v", n, err)
		}
		if msgs, _ := s.ListMessagesByThread(ctx, a.ID, "t1"); len(msgs) != 1 {
			t.Fatalf("%d messages remain, want 1", len(msgs))
		}
		// the thread still has a message, so it stays
		if n, err := s.DeleteEmptyThreads(ctx, a.ID); err != nil || n != 0 {
			t.Fatalf("DeleteEmptyThreads removed a non-empty thread: %d %v", n, err)
		}
		if _, err := s.DeleteMessagesBefore(ctx, a.ID, 1000); err != nil {
			t.Fatal(err)
		}
		if n, err := s.DeleteEmptyThreads(ctx, a.ID); err != nil || n != 1 {
			t.Fatalf("DeleteEmptyThreads: %d %v", n, err)
		}
		// blobs: listed, counted across accounts, deleted per account
		blobs, err := s.ListBlobs(ctx, a.ID)
		if err != nil || len(blobs) != 1 {
			t.Fatalf("ListBlobs: %d %v", len(blobs), err)
		}
		if refs, err := s.CountBlobRefs(ctx, "deadbeef"); err != nil || refs != 1 {
			t.Fatalf("CountBlobRefs: %d %v", refs, err)
		}
		if n, err := s.DeleteBlob(ctx, a.ID, "deadbeef"); err != nil || n != 1 {
			t.Fatalf("DeleteBlob: %d %v", n, err)
		}
		if refs, err := s.CountBlobRefs(ctx, "deadbeef"); err != nil || refs != 0 {
			t.Fatalf("refs after delete: %d %v", refs, err)
		}
	})

	t.Run("SettingsUpsertAndSecretFlag", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		if rows, err := s.ListSettings(ctx); err != nil || len(rows) != 0 {
			t.Fatalf("initial settings: %v %d", err, len(rows))
		}
		if err := s.PutSetting(ctx, store.Setting{Key: "seal", Value: "required", UpdatedAt: 100}); err != nil {
			t.Fatal(err)
		}
		if err := s.PutSetting(ctx, store.Setting{
			Key: "tunnel.tailscale.auth_key", Value: "sealed-bytes", Secret: true, UpdatedAt: 101,
		}); err != nil {
			t.Fatal(err)
		}
		// a second write to the same key REPLACES it rather than duplicating
		if err := s.PutSetting(ctx, store.Setting{Key: "seal", Value: "optional", UpdatedAt: 102}); err != nil {
			t.Fatal(err)
		}
		rows, err := s.ListSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("upsert duplicated rows: %+v", rows)
		}
		byKey := map[string]store.Setting{}
		for _, r := range rows {
			byKey[r.Key] = r
		}
		if got := byKey["seal"]; got.Value != "optional" || got.Secret || got.UpdatedAt != 102 {
			t.Fatalf("seal row: %+v", got)
		}
		if got := byKey["tunnel.tailscale.auth_key"]; !got.Secret || got.Value != "sealed-bytes" {
			t.Fatalf("secret flag lost: %+v", got)
		}
		// Unpairing has to FORGET a setting, not blank it.
		if err := s.DeleteSetting(ctx, "tunnel.tailscale.auth_key"); err != nil {
			t.Fatal(err)
		}
		rows, err = s.ListSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Key != "seal" {
			t.Fatalf("after delete: %+v", rows)
		}
		// deleting what is not there is not an error — unpair must be idempotent
		if err := s.DeleteSetting(ctx, "tunnel.tailscale.auth_key"); err != nil {
			t.Fatalf("second delete: %v", err)
		}
	})

	t.Run("CredentialsInsertAndCount", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, _ := s.CreateOwnerWithID(ctx, "", "O")
		if n, err := s.CountCredentialsByKind(ctx, "passkey"); err != nil || n != 0 {
			t.Fatalf("initial count: %v %d", err, n)
		}
		if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "passkey", Tag: "phone", Data: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "bogus", Data: []byte{1}}); err == nil {
			t.Fatal("invalid credential kind accepted")
		}
		if n, _ := s.CountCredentialsByKind(ctx, "passkey"); n != 1 {
			t.Fatalf("count after insert: %d", n)
		}
	})

	// P10-09d: the "never remove the last passkey" invariant is one statement,
	// not a read followed by a delete. Two surfaces (portal, owner MCP) can both
	// be removing at once, and check-then-delete lets both observe "there are
	// two" and both delete — leaving zero, which locks the owner out AND
	// re-opens the setup wizard to whoever reaches the node first.
	t.Run("RemoveCredentialIfNotLastKeepsTheLastOne", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, _ := s.CreateOwnerWithID(ctx, "", "O")
		var ids []string
		// Eight, not two: the invariant is "never reach zero" under ANY amount
		// of simultaneity, and a two-way race is a window narrow enough to pass
		// by luck on a fast database.
		for _, tag := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "passkey", Tag: tag, Data: []byte(tag)}); err != nil {
				t.Fatal(err)
			}
		}
		list, err := s.ListCredentialsByKind(ctx, "passkey")
		if err != nil || len(list) != 8 {
			t.Fatalf("setup: %v %d", err, len(list))
		}
		for _, c := range list {
			ids = append(ids, c.ID)
		}

		// CONCURRENTLY, because sequential removal cannot fail: a read-then-delete
		// implementation passes that, and so does an uncorrelated `SELECT
		// COUNT(*)` on Postgres, where READ COMMITTED lets two statements each
		// see "there are two" and each delete a different row. The invariant is
		// about simultaneity, so the test has to be.
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]bool, len(ids))
		errs := make([]error, len(ids))
		for i, id := range ids {
			wg.Add(1)
			go func(i int, id string) {
				defer wg.Done()
				<-start
				results[i], errs[i] = s.RemoveCredentialIfNotLast(ctx, id, "passkey")
			}(i, id)
		}
		close(start)
		wg.Wait()
		removedCount := 0
		for i := range ids {
			if errs[i] != nil {
				t.Fatal(errs[i])
			}
			if results[i] {
				removedCount++
			}
		}
		if removedCount != len(ids)-1 {
			t.Fatalf("removed %d of %d passkeys concurrently, want %d",
				removedCount, len(ids), len(ids)-1)
		}
		n, err := s.CountCredentialsByKind(ctx, "passkey")
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("passkeys left: %d, want exactly 1 — reaching zero locks the owner "+
				"out AND re-opens the setup wizard to whoever finds the node", n)
		}
		// The count is scoped to the KIND. A credential of another kind must not
		// make the last passkey look removable.
		if err := s.InsertCredential(ctx, store.Credential{OwnerID: o.ID, Kind: "oauth", Tag: "up", Data: []byte("t")}); err != nil {
			t.Fatal(err)
		}
		left, _ := s.ListCredentialsByKind(ctx, "passkey")
		if removed, err := s.RemoveCredentialIfNotLast(ctx, left[0].ID, "passkey"); err != nil || removed {
			t.Fatalf("another kind made the last passkey removable: removed=%v err=%v", removed, err)
		}
	})

	// msg_id is the SENDER's idempotency key, so the two directions are separate
	// namespaces. Both engines must accept the same msg_id once each way, look
	// each up independently, and confine a status update to the outbound row.
	// This lives in the shared suite because the constraint is enforced by the
	// schema, and the two engines express it in different DDL — Postgres swaps a
	// named constraint, SQLite rebuilds the table.
	t.Run("MsgIDIsScopedToDirection", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "dir", DisplayName: "Dir", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		for i, dir := range []string{"in", "out"} {
			if err := s.InsertMessage(ctx, store.Message{
				ID: fmt.Sprintf("d%d", i), AccountID: a.ID, ContactFpr: "sha256:p",
				MsgID: "shared", ThreadID: "t1", Direction: dir, Sender: "human",
				Kind: "text", Body: dir, Status: "delivered", CreatedAt: 100,
			}); err != nil {
				t.Fatalf("a %s message could not reuse a msg_id the other direction holds: %v", dir, err)
			}
		}
		for _, dir := range []string{"in", "out"} {
			m, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", dir, "shared")
			if err != nil {
				t.Fatalf("looking up the %s message by its key: %v", dir, err)
			}
			if m.Direction != dir || m.Body != dir {
				t.Fatalf("key (%s, shared) returned the %s row", dir, m.Direction)
			}
		}
		// A delivery outcome belongs to the message we SENT. Without the
		// direction scope this rewrote whichever row matched first, so a peer's
		// message could be marked failed by our own send.
		if err := s.SetMessageStatus(ctx, a.ID, "sha256:p", "shared", "failed"); err != nil {
			t.Fatal(err)
		}
		in, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", "in", "shared")
		if err != nil {
			t.Fatal(err)
		}
		if in.Status != "delivered" {
			t.Fatalf("an outbound delivery outcome rewrote the INBOUND row: status %q", in.Status)
		}
		out, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", "out", "shared")
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != "failed" {
			t.Fatalf("the outbound row was not updated: status %q", out.Status)
		}
	})

	// `expires` is chosen by the SENDER (PACT §7), so the column has to hold any
	// plausible epoch value. On Postgres it was INTEGER — 32-bit — where every
	// other epoch column is BIGINT: a far-future deadline made the INSERT fail
	// with "integer out of range" and the message was refused, and the column
	// stopped holding a timestamp at all in 2038.
	t.Run("MessageExpiryHoldsAFarFutureDeadline", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "exp", DisplayName: "Exp", Algo: "p256"})
		if err := s.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: "sha256:p", CreatedAt: 100, LastAt: 100}); err != nil {
			t.Fatal(err)
		}
		const farFuture = int64(1) << 34 // year 2514, comfortably past 2038
		if err := s.InsertMessage(ctx, store.Message{
			ID: "e1", AccountID: a.ID, ContactFpr: "sha256:p", MsgID: "far",
			ThreadID: "t1", Direction: "out", Sender: "human", Kind: "text",
			Body: "hi", Status: "pending", CreatedAt: 100, ExpiresAt: farFuture,
		}); err != nil {
			t.Fatalf("a far-future expires was refused by the schema: %v", err)
		}
		m, err := s.GetMessageByMsgID(ctx, a.ID, "sha256:p", "out", "far")
		if err != nil {
			t.Fatal(err)
		}
		if m.ExpiresAt != farFuture {
			t.Fatalf("expires_at round-tripped as %d, want %d", m.ExpiresAt, farFuture)
		}
	})

	t.Run("MembershipRoundTripAndFK", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		o, _ := s.CreateOwnerWithID(ctx, "", "O")
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "a", DisplayName: "A", Algo: "ed25519"})
		if err := s.AddMembership(ctx, o.ID, a.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		ms, err := s.ListMembershipsByOwner(ctx, o.ID)
		if err != nil || len(ms) != 1 || ms[0].AccountID != a.ID || ms[0].Role != "admin" {
			t.Fatalf("memberships: %v %+v", err, ms)
		}
		if err := s.AddMembership(ctx, "nope", a.ID, "admin"); err == nil {
			t.Fatal("membership with unknown owner accepted")
		}
		if err := s.RemoveMembership(ctx, o.ID, a.ID); err != nil {
			t.Fatal(err)
		}
		if ms, _ := s.ListMembershipsByOwner(ctx, o.ID); len(ms) != 0 {
			t.Fatal("membership not removed")
		}
	})

	t.Run("IntegrationsCRUD", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, err := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
		if err != nil {
			t.Fatal(err)
		}
		in, err := s.InsertIntegration(ctx, store.Integration{
			AccountID: a.ID, Slug: "gcal", Transport: "streamable-http",
			Endpoint: "https://cal.example/mcp",
		})
		if err != nil || in.ID == "" || in.Status != "disabled" || in.AuthKind != "none" {
			t.Fatalf("insert: %+v %v", in, err)
		}
		// slug unique per account
		if _, err := s.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "gcal", Transport: "sse"}); err == nil {
			t.Fatal("duplicate slug accepted")
		}
		got, err := s.GetIntegration(ctx, a.ID, "gcal")
		if err != nil || got.Endpoint != "https://cal.example/mcp" {
			t.Fatalf("get: %+v %v", got, err)
		}
		if byID, err := s.GetIntegrationByID(ctx, in.ID); err != nil || byID.Slug != "gcal" {
			t.Fatalf("get by id: %+v %v", byID, err)
		}
		if err := s.UpdateIntegrationStatus(ctx, in.ID, "ok"); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateIntegrationConfig(ctx, in.ID, "sse", "https://cal2.example/sse", "", "static"); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetIntegration(ctx, a.ID, "gcal")
		if got.Status != "ok" || got.Transport != "sse" || got.AuthKind != "static" || got.UpdatedAt < got.CreatedAt {
			t.Fatalf("after updates: %+v", got)
		}
		all, err := s.ListIntegrations(ctx, a.ID)
		if err != nil || len(all) != 1 {
			t.Fatalf("list: %v %d", err, len(all))
		}
		if err := s.UpdateIntegrationStatus(ctx, "missing", "ok"); err == nil {
			t.Fatal("status update on unknown id accepted")
		}
		if err := s.DeleteIntegration(ctx, in.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetIntegration(ctx, a.ID, "gcal"); err == nil {
			t.Fatal("deleted integration still readable")
		}
	})

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

func migrated(t *testing.T, newStore Factory) Migratable {
	t.Helper()
	s := newStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

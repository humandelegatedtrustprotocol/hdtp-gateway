package portable

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/migrations"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// removedThreads is a file's removed threads (HDTP §9.2: a thread whose contact is no row of
// contacts.csv), by root, with the names each carries.
func removedThreads(c *hdtpidentity.ExportContents) map[string][2]string {
	held := map[string]bool{}
	for _, r := range c.Contacts {
		held[r.Root] = true
	}
	out := map[string][2]string{}
	for _, t := range c.Threads {
		if !held[t.Contact] {
			out[t.Contact] = [2]string{t.ContactName, t.ContactDisplayName}
		}
	}
	return out
}

// formerContact adds Chen as an active contact with a petname and a conversation, then removes
// the row as the owner's removal does: the trigger keeps the names and that Chen was a contact.
func formerContact(t *testing.T, e env, accountID string) string {
	t.Helper()
	ctx := context.Background()
	chen := testid.NewWallet(t, "Chen Wu")
	h := chen.Issue(t, "https://chen.example/a/chen/mcp")
	_, err := e.st.InsertContact(ctx, store.Contact{AccountID: accountID, Fingerprint: chen.Fpr, SPKI: h.Key.Public().SPKI, Status: "active",
		DisplayName: "Chen Wu", Endpoint: h.Endpoint, Leaf: h.LeafDER, RootCert: chen.RootDER, CreatedAt: 1790000040, PinnedAt: 1790000040})
	must(t, err)
	must(t, e.st.SetContactPetname(ctx, accountID, chen.Fpr, "Chen, old team"))
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "t-chen", AccountID: accountID, ContactFpr: chen.Fpr, Topic: "handover", CreatedAt: 1790000041, LastAt: 1790000042}))
	must(t, e.st.InsertMessage(ctx, store.Message{ID: "mc1", AccountID: accountID, ContactFpr: chen.Fpr, MsgID: "c-1", ThreadID: "t-chen",
		Direction: "in", Sender: "human", Kind: "text", Body: "the keys are in the drawer", Status: "delivered", CreatedAt: 1790000042}))
	must(t, e.st.DeleteContact(ctx, accountID, chen.Fpr))
	return chen.Fpr
}

// HDTP §9.2 (SEP-0004): a former contact's conversation travels as a removed thread carrying the
// names it kept; its root is not a contact, and nothing of it is left out.
func TestAFormerContactsConversationTravelsAsARemovedThread(t *testing.T) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			e := newEnv(t, eng.open)
			s := seed(t, e)
			chen := formerContact(t, e, s.accountID)
			file, res := exportOf(t, e, "alina")
			got, err := hdtpidentity.ReadExportZip(zipReader(t, file), s.me.Fpr, time.Now(), ImportCeiling)
			must(t, err)
			if rt := removedThreads(got); len(rt) != 1 || rt[chen] != [2]string{"Chen, old team", "Chen Wu"} {
				t.Fatalf("removed threads: %+v", rt)
			}
			for _, c := range got.Contacts {
				if c.Root == chen {
					t.Fatal("a former contact was written as a contact")
				}
			}
			carried := false
			for _, th := range got.Threads {
				carried = carried || th.ID == "t-chen" && th.Contact == chen
			}
			if !carried || res.Removed != 1 || res.Threads != 2 || res.Messages != 5 {
				t.Fatalf("the former contact's thread is not carried: %+v, result %+v", got.Threads, res)
			}
			if strings.Contains(strings.Join(res.LeftOut, "\n"), chen) {
				t.Fatalf("a former contact's conversation is said to be left out: %v", res.LeftOut)
			}
		})
	}
}

// A stranger whose request was never accepted, blocked or not, was never a contact: when its row
// goes its thread stays here, and is named in the report by its id and the reason (HDTP §9.2).
func TestAStrangersConversationStaysWhenItsRowGoes(t *testing.T) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t, eng.open)
			s := seed(t, e)
			blocked := testid.NewWallet(t, "Pest")
			bh := blocked.Issue(t, "https://pest.example/a/p/mcp")
			_, err := e.st.InsertContact(ctx, store.Contact{AccountID: s.accountID, Fingerprint: blocked.Fpr, SPKI: bh.Key.Public().SPKI, Status: "blocked",
				Endpoint: bh.Endpoint, Leaf: bh.LeafDER, CreatedAt: 1790000050, PinnedAt: 1790000050})
			must(t, err)
			must(t, e.st.InsertThread(ctx, store.Thread{ID: "t-pest", AccountID: s.accountID, ContactFpr: blocked.Fpr, CreatedAt: 1790000050, LastAt: 1790000050}))
			for _, fpr := range []string{s.strangerID, blocked.Fpr} {
				must(t, e.st.DeleteContact(ctx, s.accountID, fpr))
			}
			file, res := exportOf(t, e, "alina")
			got, err := hdtpidentity.ReadExportZip(zipReader(t, file), s.me.Fpr, time.Now(), ImportCeiling)
			must(t, err)
			if rt := removedThreads(got); len(rt) != 0 || len(got.Threads) != 1 {
				t.Fatalf("a stranger travels: removed %+v, threads %+v", rt, got.Threads)
			}
			joined := strings.Join(res.LeftOut, "\n")
			for _, want := range []string{
				"thread t-stranger: a conversation of 1 message(s) with " + s.strangerID + ", who this host has no record of as a contact",
				"thread t-pest: a conversation of 0 message(s) with " + blocked.Fpr + ", who this host has no record of as a contact",
			} {
				if !strings.Contains(joined, want) {
					t.Fatalf("left out:\n%s\nwant %q", joined, want)
				}
			}
		})
	}
}

// A former contact who asks again is a request this host holds, which stays with it; the
// conversation from when they were a contact travels as a removed thread (HDTP §9.2, the status cell).
func TestAFormerContactAskingAgainTravelsAndTheRequestStays(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	chen := formerContact(t, e, s.accountID)
	_, err := e.st.InsertContact(ctx, store.Contact{AccountID: s.accountID, Fingerprint: chen, Status: "pending_in", CreatedAt: 1790000060, PinnedAt: 1790000060})
	must(t, err)
	file, res := exportOf(t, e, "alina")
	got, err := hdtpidentity.ReadExportZip(zipReader(t, file), s.me.Fpr, time.Now(), ImportCeiling)
	must(t, err)
	if rt := removedThreads(got); len(rt) != 1 || rt[chen][0] != "Chen, old team" {
		t.Fatalf("removed threads: %+v", rt)
	}
	joined := strings.Join(res.LeftOut, "\n")
	if !strings.Contains(joined, "a request from "+chen+" that was never accepted") || strings.Contains(joined, "thread t-chen") {
		t.Fatalf("left out:\n%s", joined)
	}
}

// The round trip: the conversation arrives labelled as a former contact's, no contact is written
// for it, and a contact added later with that root takes it back (HDTP §9.2 step 3).
func TestARemovedConversationArrivesAndNeverBecomesAContact(t *testing.T) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			ctx := context.Background()
			src, dst := newEnv(t, eng.open), newEnv(t, eng.open)
			s := seed(t, src)
			chen := formerContact(t, src, s.accountID)
			file, _ := exportOf(t, src, "alina")
			p, res, err := importFile(t, dst, file, "alina", time.Now())
			must(t, err)
			if res.Removed != 1 || res.Contacts != 1 || len(p.Removed) != 1 || p.Removed[0] != (RemovedContact{Root: chen, Name: "Chen, old team", DisplayName: "Chen Wu"}) {
				t.Fatalf("import: %+v", res)
			}
			if _, err := dst.st.GetContact(ctx, p.AccountID, chen); err == nil {
				t.Fatal("a removed thread's root was written as a contact")
			}
			th, err := dst.st.GetThread(ctx, p.AccountID, "t-chen")
			must(t, err)
			if th.ContactFpr != chen || th.KeptPetname != "Chen, old team" || th.KeptDisplayName != "Chen Wu" || !th.KeptWasContact {
				t.Fatalf("the thread as imported: %+v", th)
			}
			// No handshake is due to it: only the written contact is marked for one.
			cs, err := dst.st.ListContacts(ctx, p.AccountID)
			must(t, err)
			if len(cs) != 1 || cs[0].Fingerprint != s.peer.Fpr {
				t.Fatalf("contacts after the import: %+v", cs)
			}
			// It travels on again from here: the second host's export carries it as the first did.
			again, _ := exportOf(t, dst, "alina")
			got, err := hdtpidentity.ReadExportZip(zipReader(t, again), s.me.Fpr, time.Now(), ImportCeiling)
			must(t, err)
			if rt := removedThreads(got); len(rt) != 1 || rt[chen] != [2]string{"Chen, old team", "Chen Wu"} {
				t.Fatalf("exported again: %+v", rt)
			}
		})
	}
}

// Into an identity that holds the root as a contact, of any status, the thread is that contact's:
// nothing is written over the row and no second contact appears (HDTP §9.2 step 3).
func TestARemovedConversationJoinsAContactHeldHere(t *testing.T) {
	ctx := context.Background()
	src, dst := newEnv(t, sqliteStore), newEnv(t, sqliteStore)
	s := seed(t, src)
	chen := formerContact(t, src, s.accountID)
	file, _ := exportOf(t, src, "alina")
	a, err := dst.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: "p256"})
	must(t, err)
	must(t, dst.st.SetAccountRoot(ctx, a.ID, s.me.Fpr, s.me.RootDER))
	_, err = dst.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: chen, Status: "pending_in", DisplayName: "Chen again", CreatedAt: 1790000070, PinnedAt: 1790000070})
	must(t, err)
	_, res, err := importFile(t, dst, file, "alina", time.Now())
	must(t, err)
	if res.Removed != 0 {
		t.Fatalf("a root held here counted as a removed contact written: %+v", res)
	}
	// The same file again writes nothing as removed either: its thread is here already.
	_, again, err := importFile(t, dst, file, "alina", time.Now())
	must(t, err)
	if again.Removed != 0 {
		t.Fatalf("a removed thread here already counted again: %+v", again)
	}
	c, err := dst.st.GetContact(ctx, a.ID, chen)
	must(t, err)
	if c.Status != "pending_in" || c.DisplayName != "Chen again" {
		t.Fatalf("the held row was changed: %+v", c)
	}
	th, err := dst.st.GetThread(ctx, a.ID, "t-chen")
	must(t, err)
	if th.ContactFpr != chen {
		t.Fatalf("the thread: %+v", th)
	}
}

// beforeKeptWasContact opens a store whose schema stops at migration 0002, before threads kept
// whether their root was a contact, so a test can write what a node held then and migrate it.
func beforeKeptWasContact(t *testing.T, name string) (store.Store, func() error) {
	t.Helper()
	ctx := context.Background()
	if name == "sqlite" {
		path := filepath.Join(t.TempDir(), "hdtp.db")
		st, err := store.OpenSQLite(path)
		must(t, err)
		t.Cleanup(func() { st.Close() })
		db, err := sql.Open("sqlite", "file:"+path)
		must(t, err)
		t.Cleanup(func() { db.Close() })
		sub, err := fs.Sub(migrations.SQLite, "sqlite")
		must(t, err)
		p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
		must(t, err)
		_, err = p.UpTo(ctx, 2)
		must(t, err)
		return st, func() error { return st.Migrate(ctx) }
	}
	dsn := os.Getenv("HDTP_TEST_POSTGRES_DSN")
	pgSeq++
	db := fmt.Sprintf("hdtp_portable_%d_%d", os.Getpid(), pgSeq)
	admin, err := pgx.Connect(ctx, dsn)
	must(t, err)
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+db)
	_, err = admin.Exec(ctx, "CREATE DATABASE "+db)
	must(t, err)
	admin.Close(ctx)
	i := strings.LastIndex(dsn, "/")
	rest, query := dsn[i+1:], ""
	if j := strings.Index(rest, "?"); j >= 0 {
		query = rest[j:]
	}
	target := dsn[:i+1] + db + query
	st, err := store.OpenPostgres(ctx, target)
	must(t, err)
	t.Cleanup(func() { st.Close() })
	conn, err := sql.Open("pgx", target)
	must(t, err)
	t.Cleanup(func() { conn.Close() })
	sub, err := fs.Sub(migrations.Postgres, "postgres")
	must(t, err)
	p, err := goose.NewProvider(goose.DialectPostgres, conn, sub)
	must(t, err)
	_, err = p.UpTo(ctx, 2)
	must(t, err)
	return st, func() error { return st.Migrate(ctx) }
}

// Migration 0003 on a node that removed contacts before it: a thread that holds a message was a
// contact's, since only a contact writes one (inbound at the contact tier, outbound to an active
// contact alone; a request's note is never stored), so a former contact's conversation travels as a
// removed thread with the names it kept. A thread with no message left proves nothing and stays,
// named as one with a root this host has no record of as a contact — the gap the migration cannot
// close. A stranger whose request expired left no thread at all: its note was never written.
func TestMigration0003KeepsAFormerContactsConversationRemovedBeforeIt(t *testing.T) {
	names := []string{"sqlite"}
	if os.Getenv("HDTP_TEST_POSTGRES_DSN") != "" {
		names = append(names, "postgres")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			st, migrate := beforeKeptWasContact(t, name)
			e := env{st: st, blobs: messaging.BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}}
			me := testid.NewWallet(t, "Alina Rao")
			a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: "p256"})
			must(t, err)
			must(t, st.SetAccountRoot(ctx, a.ID, me.Fpr, me.RootDER))
			chen := formerContact(t, e, a.ID)
			dana := testid.NewWallet(t, "Dana")
			_, err = st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: dana.Fpr, Status: "active", DisplayName: "Dana", CreatedAt: 1790000080, PinnedAt: 1790000080})
			must(t, err)
			must(t, st.InsertThread(ctx, store.Thread{ID: "t-dana", AccountID: a.ID, ContactFpr: dana.Fpr, CreatedAt: 1790000081, LastAt: 1790000081}))
			must(t, st.DeleteContact(ctx, a.ID, dana.Fpr))

			must(t, migrate())
			for id, want := range map[string]bool{"t-chen": true, "t-dana": false} {
				th, err := st.GetThread(ctx, a.ID, id)
				must(t, err)
				if th.KeptWasContact != want {
					t.Fatalf("%s: kept_was_contact %v after the migration, want %v", id, th.KeptWasContact, want)
				}
			}
			file, res := exportOf(t, e, "alina")
			got, err := hdtpidentity.ReadExportZip(zipReader(t, file), me.Fpr, time.Now(), ImportCeiling)
			must(t, err)
			if rt := removedThreads(got); len(rt) != 1 || rt[chen] != [2]string{"Chen, old team", "Chen Wu"} {
				t.Fatalf("removed threads: %+v", rt)
			}
			want := "thread t-dana: a conversation of 0 message(s) with " + dana.Fpr + ", who this host has no record of as a contact"
			if joined := strings.Join(res.LeftOut, "\n"); !strings.Contains(joined, want) {
				t.Fatalf("left out:\n%s\nwant %q", joined, want)
			}
		})
	}
}

// A root's names are, per name, the newest its threads kept that is not empty (store.KeptNamesByRoot):
// a former contact accepted again under a row with no name, and removed again, leaves a newer thread
// that kept no name, and the petname the owner gave them, and the name they gave themselves, still
// travel and still label the conversation.
func TestARemovedThreadCarriesTheNewestNameEachOfItsThreadsKept(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	chen := formerContact(t, e, s.accountID)
	_, err := e.st.InsertContact(ctx, store.Contact{AccountID: s.accountID, Fingerprint: chen, Status: "active", CreatedAt: 1790000090, PinnedAt: 1790000090})
	must(t, err)
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "t-chen-2", AccountID: s.accountID, ContactFpr: chen, CreatedAt: 1790000091, LastAt: 1790000091}))
	must(t, e.st.InsertMessage(ctx, store.Message{ID: "mc2", AccountID: s.accountID, ContactFpr: chen, MsgID: "c-2", ThreadID: "t-chen-2",
		Direction: "in", Sender: "human", Kind: "text", Body: "back again", Status: "delivered", CreatedAt: 1790000091}))
	must(t, e.st.DeleteContact(ctx, s.accountID, chen))
	newer, err := e.st.GetThread(ctx, s.accountID, "t-chen-2")
	must(t, err)
	if newer.KeptPetname != "" || newer.KeptDisplayName != "" {
		t.Fatalf("the newer thread kept names, so this case proves nothing: %+v", newer)
	}
	file, _ := exportOf(t, e, "alina")
	got, err := hdtpidentity.ReadExportZip(zipReader(t, file), s.me.Fpr, time.Now(), ImportCeiling)
	must(t, err)
	for _, th := range got.Threads {
		if th.Contact == chen && (th.ContactName != "Chen, old team" || th.ContactDisplayName != "Chen Wu") {
			t.Fatalf("thread %s carries %q, %q", th.ID, th.ContactName, th.ContactDisplayName)
		}
	}
}

// A name a contact chose arrives as the file says and is stripped where the import takes it in, by
// the rule a card's FN passes (identity.StripDisplayName, HDTP §3): a removed thread's
// contact_display_name and a contact's display_name with a bidirectional override land without it.
func TestAnImportedContactsOwnNameIsStrippedWhereItEnters(t *testing.T) {
	ctx := context.Background()
	src, dst := newEnv(t, sqliteStore), newEnv(t, sqliteStore)
	s := seed(t, src)
	held, err := src.st.GetContact(ctx, s.accountID, s.peer.Fpr)
	must(t, err)
	must(t, src.st.UpdateContactCard(ctx, s.accountID, s.peer.Fpr, held.Card, "\u202eBharat\u200b Mehta"))
	dana := testid.NewWallet(t, "Dana")
	_, err = src.st.InsertContact(ctx, store.Contact{AccountID: s.accountID, Fingerprint: dana.Fpr, Status: "active", DisplayName: "\u202eDana\u2066", CreatedAt: 1790000100, PinnedAt: 1790000100})
	must(t, err)
	must(t, src.st.InsertThread(ctx, store.Thread{ID: "t-dana", AccountID: s.accountID, ContactFpr: dana.Fpr, CreatedAt: 1790000101, LastAt: 1790000101}))
	must(t, src.st.InsertMessage(ctx, store.Message{ID: "md1", AccountID: s.accountID, ContactFpr: dana.Fpr, MsgID: "d-1", ThreadID: "t-dana",
		Direction: "in", Sender: "human", Kind: "text", Body: "hello", Status: "delivered", CreatedAt: 1790000101}))
	must(t, src.st.DeleteContact(ctx, s.accountID, dana.Fpr))
	file, _ := exportOf(t, src, "alina")
	got, err := hdtpidentity.ReadExportZip(zipReader(t, file), s.me.Fpr, time.Now(), ImportCeiling)
	must(t, err)
	if rt := removedThreads(got); rt[dana.Fpr][1] != "\u202eDana\u2066" {
		t.Fatalf("the file does not carry the name as written, so this case proves nothing: %+v", rt)
	}
	p, _, err := importFile(t, dst, file, "alina", time.Now())
	must(t, err)
	c, err := dst.st.GetContact(ctx, p.AccountID, s.peer.Fpr)
	must(t, err)
	if c.DisplayName != "Bharat Mehta" {
		t.Fatalf("contact display_name as imported: %q", c.DisplayName)
	}
	th, err := dst.st.GetThread(ctx, p.AccountID, "t-dana")
	must(t, err)
	if th.KeptDisplayName != "Dana" {
		t.Fatalf("kept display name as imported: %q", th.KeptDisplayName)
	}
}

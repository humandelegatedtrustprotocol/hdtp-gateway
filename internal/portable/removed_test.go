package portable

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
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
				"thread t-stranger: 1 message(s) with " + s.strangerID + ", who was never a contact",
				"thread t-pest: 0 message(s) with " + blocked.Fpr + ", who was never a contact",
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
	_, _, err = importFile(t, dst, file, "alina", time.Now())
	must(t, err)
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

package portable

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/messaging"
	"github.com/pact-cloud/pact-gateway/internal/testid"
	pactidentity "github.com/pact-cloud/pact-identity/go"
	"github.com/pact-cloud/pact-identity/go/exportcorpus"
)

// What must never be in an export, planted as recognisable strings so the test can look for them
// in the file's BYTES. Reading the rows back would prove only that the rows this package wrote are
// the rows it wrote; the question is what else is in the file.
const (
	secretLeafKey     = "LEAF-PRIVATE-KEY-MATERIAL-7f3a"
	secretLedgerKey   = "SUPERSEDED-LEAF-KEY-MATERIAL-91bc"
	secretSetting     = "SETTING-TUNNEL-AUTH-KEY-42de"
	secretToken       = "OWNER-MCP-TOKEN-HASH-c0de"
	secretInviteLabel = "INVITE-LABEL-FOR-THE-CONFERENCE-5e11"
	secretIntegration = "https://INTEGRATION-UPSTREAM-ENDPOINT.example/mcp"
	strangerNote      = "A STRANGER'S REQUEST NOTE-77aa"
)

type env struct {
	st    store.Store
	blobs messaging.BlobDir
}

func newEnv(t *testing.T, open func(t *testing.T) store.Store) env {
	t.Helper()
	st := open(t)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return env{st: st, blobs: messaging.BlobDir{Root: filepath.Join(t.TempDir(), "blobs")}}
}

func sqliteStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

type engine struct {
	name string
	open func(t *testing.T) store.Store
}

// engines is SQLite always, and Postgres when the pre-push hook provides one.
func engines(t *testing.T) []engine {
	out := []engine{{"sqlite", sqliteStore}}
	if dsn := os.Getenv("PACT_TEST_POSTGRES_DSN"); dsn != "" {
		out = append(out, engine{"postgres", func(t *testing.T) store.Store {
			t.Helper()
			pgSeq++
			name := fmt.Sprintf("pact_portable_%d_%d", os.Getpid(), pgSeq)
			admin, err := pgx.Connect(context.Background(), dsn)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
			if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+name); err != nil {
				t.Fatal(err)
			}
			admin.Close(context.Background())
			i := strings.LastIndex(dsn, "/")
			rest, query := dsn[i+1:], ""
			if j := strings.Index(rest, "?"); j >= 0 {
				query = rest[j:]
			}
			st, err := store.OpenPostgres(context.Background(), dsn[:i+1]+name+query)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			return st
		}})
	}
	return out
}

var pgSeq int

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// seeded is what seed made, for the tests to look for.
type seeded struct {
	me, peer   *testid.Wallet
	host       *testid.Host
	mediaHash  string
	accountID  string
	strangerID string
}

// seed fills a node the way a lived-in one is filled: an identity with a contact, a conversation
// holding text, a file and a link — and beside them everything a host accumulates that is nobody
// else's business, and a stranger's request that is not the person's either.
func seed(t *testing.T, e env) seeded {
	t.Helper()
	ctx := context.Background()
	s := seeded{me: testid.NewWallet(t, "Alina Rao"), peer: testid.NewWallet(t, "Bharat Mehta")}
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina Rao", Algo: "p256"})
	must(t, err)
	s.accountID = a.ID
	must(t, e.st.SetAccountKey(ctx, a.ID, "sha256:leaf-kid", []byte(secretLeafKey)))
	must(t, e.st.SetAccountRoot(ctx, a.ID, s.me.Fpr, s.me.RootDER))
	must(t, e.st.InsertLeaf(ctx, store.Leaf{AccountID: a.ID, Kid: "sha256:old-kid", Leaf: []byte("leaf-der"), KeySealed: []byte(secretLedgerKey),
		NotBefore: 1, NotAfter: 9, State: "superseded", Endpoint: "https://alina.example/a/alina/mcp"}))

	s.host = s.peer.Issue(t, "https://bharat.example/a/bharat/mcp")
	inv, err := e.st.InsertInvite(ctx, store.Invite{AccountID: a.ID, TokenHash: []byte("invite-hash"), ExpiresAt: 99, MaxUses: 1, Label: secretInviteLabel, CreatedAt: 3})
	must(t, err)
	_, err = e.st.InsertContact(ctx, store.Contact{
		AccountID: a.ID, Fingerprint: s.peer.Fpr, SPKI: s.host.Key.Public.SPKI, Status: "active", Preset: "friend",
		Permissions: []string{"message.text", "message.media"}, DisplayName: "Bharat Mehta", Card: s.host.Card("Bharat Mehta", "required"),
		CreatedAt: 1790000000, PinnedAt: 1790000001, InviteID: inv.ID, Endpoint: s.host.Endpoint, Leaf: s.host.LeafDER,
		ChainSentKid: "sha256:leaf-kid", RootCert: s.peer.RootDER,
	})
	must(t, err)
	must(t, e.st.SetContactPetname(ctx, a.ID, s.peer.Fpr, "B, from the conference"))
	must(t, e.st.UpdateContactTrust(ctx, a.ID, s.peer.Fpr, "may_instruct"))

	s.mediaHash, err = e.blobs.Put([]byte("a photograph of a whiteboard"))
	must(t, err)
	must(t, e.st.InsertBlob(ctx, store.Blob{AccountID: a.ID, Hash: s.mediaHash, Size: 28, Mime: "image/png", Filename: "whiteboard.png", CreatedAt: 1790000021}))
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "t1", AccountID: a.ID, ContactFpr: s.peer.Fpr, Topic: "the plan", CreatedAt: 1790000020, LastAt: 1790000024}))
	file, _ := json.Marshal(messaging.MediaMeta{Filename: "whiteboard.png", Mime: "image/png", Hash: s.mediaHash, Size: 28})
	link, _ := json.Marshal(messaging.MediaMeta{Filename: "slides.pdf", Mime: "application/pdf", URL: "https://files.example/slides.pdf"})
	for i, m := range []store.Message{
		{ID: "m1", MsgID: "msg-1", Direction: "in", Sender: "human", Kind: "text", Body: "shall we meet?", Status: "delivered", CreatedAt: 1790000020},
		{ID: "m2", MsgID: "msg-2", Direction: "out", Sender: "human", Kind: "media", Body: string(file), Status: "delivered", CreatedAt: 1790000022, ReplyTo: "msg-1"},
		{ID: "m3", MsgID: "msg-3", Direction: "in", Sender: "agent", Kind: "media", Body: string(link), Status: "queued_for_human", CreatedAt: 1790000023},
		{ID: "m4", MsgID: "msg-4", Direction: "out", Sender: "agent", Kind: "text", Body: "never left this host", Status: "pending", CreatedAt: 1790000024, ExpiresAt: 1790099999, Attempts: 4, NextAttemptAt: 1790055555},
	} {
		m.AccountID, m.ContactFpr, m.ThreadID = a.ID, s.peer.Fpr, "t1"
		if err := e.st.InsertMessage(ctx, m); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}

	// A stranger's request, and the note that came with it: this host's business, not a contact.
	stranger := testid.NewWallet(t, "Somebody")
	sh := stranger.Issue(t, "https://somebody.example/a/s/mcp")
	_, err = e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: stranger.Fpr, SPKI: sh.Key.Public.SPKI, Status: "pending_in",
		Endpoint: sh.Endpoint, Leaf: sh.LeafDER, CreatedAt: 1790000030, PinnedAt: 1790000030})
	must(t, err)
	s.strangerID = stranger.Fpr
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "t-stranger", AccountID: a.ID, ContactFpr: stranger.Fpr, Topic: "hello", CreatedAt: 1790000030, LastAt: 1790000030}))
	must(t, e.st.InsertMessage(ctx, store.Message{ID: "ms", AccountID: a.ID, ContactFpr: stranger.Fpr, MsgID: "s-1", ThreadID: "t-stranger",
		Direction: "in", Sender: "human", Kind: "text", Body: strangerNote, Status: "delivered", CreatedAt: 1790000030}))

	// The host's own business.
	must(t, e.st.PutSetting(ctx, store.Setting{Key: "tunnel.auth_key", Value: secretSetting, Secret: true, UpdatedAt: 5}))
	o, err := e.st.CreateOwnerWithID(ctx, "owner-1", "The Owner")
	must(t, err)
	must(t, e.st.InsertToken(ctx, "tok-1", o.ID, "laptop", []byte(secretToken), a.ID, 6))
	_, err = e.st.InsertIntegration(ctx, store.Integration{AccountID: a.ID, Slug: "calendar", Transport: "streamable-http", Endpoint: secretIntegration, AuthKind: "static", Status: "ok"})
	must(t, err)
	return s
}

var exportedAt = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func exportOf(t *testing.T, e env, slug string) ([]byte, Result) {
	t.Helper()
	var buf bytes.Buffer
	res, err := Export(context.Background(), e.st, e.blobs, &buf, slug, "pact-gateway test", exportedAt)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return buf.Bytes(), res
}

func zipReader(t *testing.T, b []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		t.Fatal(err)
	}
	return zr
}

// importFile reads and applies a file, as `import -yes` does.
func importFile(t *testing.T, e env, b []byte, slug string, now time.Time) (*Plan, Result, error) {
	t.Helper()
	p, err := Read(context.Background(), e.st, zipReader(t, b), slug, now)
	if err != nil {
		return nil, Result{}, err
	}
	res, err := p.Apply(context.Background(), e.st, e.blobs)
	return p, res, err
}

// The rule, held where it can be broken: in the file. An export is one identity's contacts, its
// conversations and their files. Everything else a host holds stays with the host.
func TestAnExportCarriesContactsChatsAndFilesAndNothingElse(t *testing.T) {
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	file, res := exportOf(t, e, "alina")

	zr := zipReader(t, file)
	var names []string
	var all []byte
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		must(t, err)
		b, err := io.ReadAll(rc)
		must(t, err)
		rc.Close()
		all = append(all, b...)
	}
	sort.Strings(names)
	want := []string{"contacts.csv", "manifest.json", "media/", "media/" + s.mediaHash, "messages.jsonl", "threads.csv"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("members: %v, want exactly %v", names, want)
	}
	// Nothing planted is anywhere in it: the whole decompressed file is searched.
	for _, secret := range []string{secretLeafKey, secretLedgerKey, secretSetting, secretToken, secretInviteLabel, secretIntegration,
		strangerNote, s.strangerID, "sha256:leaf-kid", "sha256:old-kid", "tunnel.auth_key", "invite-hash", "may_instruct", "BEGIN:VCARD"} {
		if bytes.Contains(all, []byte(secret)) {
			t.Errorf("the export contains %q, which is not the person's", secret)
		}
	}
	// It is a file the core reads whole, as its owner's.
	got, err := pactidentity.ReadExportZip(zr, s.me.Fpr, time.Now(), ImportCeiling)
	if err != nil {
		t.Fatalf("the core refuses the node's own export: %v", err)
	}
	if len(got.Contacts) != 1 || len(got.Threads) != 1 || len(got.Messages) != 4 || len(got.Media) != 1 {
		t.Fatalf("the export holds %d contacts, %d threads, %d messages, %d files", len(got.Contacts), len(got.Threads), len(got.Messages), len(got.Media))
	}
	if res.Contacts != 1 || res.Threads != 1 || res.Messages != 4 || res.Media != 1 {
		t.Fatalf("export says it wrote %+v", res)
	}
	if len(res.LeftOut) != 2 {
		t.Fatalf("the stranger's request and its conversation must be left out, and said to be: %v", res.LeftOut)
	}
	c := got.Contacts[0]
	if c.Root != s.peer.Fpr || c.Name != "B, from the conference" || c.Leaf == nil || c.RootCert == nil || !c.WasActive ||
		strings.Join(c.Permissions, " ") != "message.media message.text" {
		t.Fatalf("the contact as exported: %+v", c)
	}
	byID := map[string]pactidentity.MessageRow{}
	for _, m := range got.Messages {
		byID[m.ID] = m
	}
	// The file message's description is lifted into its attachment; the link travels as the body.
	if m := byID["m2"]; m.Body != "" || len(m.Attachments) != 1 || m.Attachments[0].File != s.mediaHash || m.Attachments[0].Filename != "whiteboard.png" || m.ReplyTo == nil || *m.ReplyTo != "msg-1" {
		t.Fatalf("the file message: %+v", m)
	}
	if m := byID["m3"]; m.Body != "https://files.example/slides.pdf" || len(m.Attachments) != 0 || m.Status != "delivered" {
		t.Fatalf("the link message: %+v", m)
	}
	if m := byID["m4"]; m.Status != "queued" {
		t.Fatalf("an undelivered message travels queued: %+v", m)
	}
}

// Every file of the shared corpus (pact-identity/go/exportcorpus), imported into the identity it
// belongs to: each hostile file is refused with the words cases.json names — the core's exactly,
// and the host's (a file's bytes as decompressed, UTF-8, a media file's own hash) in the words
// CONTRACT §6.2 gives both hosts — and nothing is written. Each valid file is taken in whole.
func TestTheCorpusIsImportedAsTheCoreReadsIt(t *testing.T) {
	raw, err := fs.ReadFile(exportcorpus.FS, "cases.json")
	must(t, err)
	var idx exportcorpus.Index
	must(t, json.Unmarshal(raw, &idx))
	now, err := time.Parse(time.RFC3339, idx.Now)
	must(t, err)
	if len(idx.Cases) < 30 {
		t.Fatalf("the corpus names %d cases; it has one per check of §9.2, and fewer means this read it wrong", len(idx.Cases))
	}
	accepted, refused := 0, 0
	for _, eng := range engines(t) {
		for _, c := range idx.Cases {
			t.Run(eng.name+"/"+c.File, func(t *testing.T) {
				ctx := context.Background()
				e := newEnv(t, eng.open)
				a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
				must(t, err)
				must(t, e.st.SetAccountRoot(ctx, a.ID, idx.Owner, nil))
				b, err := fs.ReadFile(exportcorpus.FS, c.File)
				must(t, err)
				_, res, err := importFile(t, e, b, "alina", now)
				if c.Accept == nil {
					refused++
					if !errors.Is(err, ErrRefused) {
						t.Fatalf("%s (%s) was not refused: %v", c.File, c.About, err)
					}
					why := strings.TrimPrefix(err.Error(), ErrRefused.Error()+": ")
					switch {
					case c.Refusal != "" && why != c.Refusal:
						t.Fatalf("%s: refused with\n  %q\nwant\n  %q", c.File, why, c.Refusal)
					case c.RefusalPrefix != "" && !strings.HasPrefix(why, c.RefusalPrefix):
						t.Fatalf("%s: refused with %q, want it to begin %q", c.File, why, c.RefusalPrefix)
					}
					if cs, _ := e.st.ListContacts(ctx, a.ID); len(cs) != 0 {
						t.Fatalf("%s was refused and %d contact(s) were written", c.File, len(cs))
					}
					if ts, _ := e.st.ListThreadsByAccount(ctx, a.ID); len(ts) != 0 {
						t.Fatalf("%s was refused and %d thread(s) were written", c.File, len(ts))
					}
					if entries, _ := os.ReadDir(e.blobs.Root); len(entries) != 0 {
						t.Fatalf("%s was refused and files were written", c.File)
					}
					return
				}
				accepted++
				if err != nil {
					t.Fatalf("%s (%s) was refused: %v", c.File, c.About, err)
				}
				if res.Contacts != c.Accept.Contacts || res.Threads != c.Accept.Threads || res.Messages != c.Accept.Messages || res.Media != c.Accept.Media {
					t.Fatalf("%s: imported %+v, want %+v", c.File, res, *c.Accept)
				}
				cs, err := e.st.ListContacts(ctx, a.ID)
				must(t, err)
				pinned := 0
				leafless := map[string]bool{}
				for _, ct := range cs {
					if !ct.HandshakeDue {
						t.Fatalf("%s: contact %s arrived without the mark that it is owed a handshake", c.File, ct.Fingerprint)
					}
					if len(ct.Leaf) > 0 {
						pinned++
					} else {
						leafless[ct.Fingerprint] = true
					}
				}
				// Leafless names the rows whose file leaf the reader did not answer (it did not validate
				// at the row's endpoint): each is pinned by its root alone.
				if pinned != c.Accept.Pinned {
					t.Fatalf("%s: %d pinned, %d leafless; want %d and %v", c.File, pinned, len(leafless), c.Accept.Pinned, c.Accept.Leafless)
				}
				for _, root := range c.Accept.Leafless {
					if !leafless[root] {
						t.Fatalf("%s: %s must be pinned by its root alone", c.File, root)
					}
				}
			})
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the corpus ran %d accepted and %d refused; both kinds must run", accepted, refused)
	}
}

// A slug that is not here is made KEYLESS, holding only the root the file names: no certificate,
// no key, no leaf. The wallet's first leaf there must be under that root (identity's
// TestAnImportedSlugHoldsOnlyItsRootUntilTheFirstChainInstalls holds the install to it).
func TestANewSlugHoldsOnlyTheFilesRoot(t *testing.T) {
	ctx := context.Background()
	raw, _ := fs.ReadFile(exportcorpus.FS, "cases.json")
	var idx exportcorpus.Index
	must(t, json.Unmarshal(raw, &idx))
	now, _ := time.Parse(time.RFC3339, idx.Now)
	valid, err := fs.ReadFile(exportcorpus.FS, "valid-export.zip")
	must(t, err)

	e := newEnv(t, sqliteStore)
	p, _, err := importFile(t, e, valid, "moved-here", now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.New {
		t.Fatal("an import into a slug that was not here must say it made one")
	}
	a, err := e.st.GetAccountBySlug(ctx, "moved-here")
	must(t, err)
	if a.RootFingerprint != idx.Owner || len(a.RootCert) != 0 {
		t.Fatalf("the new slug holds root %q and %d bytes of certificate; want the file's owner and none", a.RootFingerprint, len(a.RootCert))
	}
	if sealed, _ := e.st.GetAccountSealedKey(ctx, a.ID); len(sealed) != 0 {
		t.Fatalf("an imported identity arrived holding %d bytes of key", len(sealed))
	}
	if leaves, _ := e.st.ListLeaves(ctx, a.ID); len(leaves) != 0 {
		t.Fatalf("an imported identity arrived with a ledger: %+v", leaves)
	}
	// One identity, one slug: the same root under another slug is refused, and writes nothing.
	if _, _, err := importFile(t, e, valid, "again", now); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), `already on this node as "moved-here"`) {
		t.Fatalf("the same root imported under a second slug: %v", err)
	}
	if _, err := e.st.GetAccountBySlug(ctx, "again"); err == nil {
		t.Fatal("a refused import made the slug anyway")
	}
	// And a slug that is somebody else is refused in the core's words for a file that is not its.
	other := testid.NewWallet(t, "Somebody Else")
	b, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "someone", DisplayName: "Someone", Algo: "p256"})
	must(t, err)
	must(t, e.st.SetAccountRoot(ctx, b.ID, other.Fpr, other.RootDER))
	if _, _, err := importFile(t, e, valid, "someone", now); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "manifest.json: owner: the file is "+idx.Owner+"'s, not this identity's") {
		t.Fatalf("a file imported into another identity: %v", err)
	}
	// A slug the wallet never certified cannot be any file's.
	_, err = e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "nobody-yet", DisplayName: "Nobody", Algo: "p256"})
	must(t, err)
	if _, _, err := importFile(t, e, valid, "nobody-yet", now); !errors.Is(err, ErrRefused) {
		t.Fatalf("a file imported into an identity with no root: %v", err)
	}
}

// Importing into the identity the file belongs to MERGES (PACT §9.2 step 2, export_merge): a
// contact held with a leaf keeps its pin whatever the file says, and the difference is shown; a
// contact held with no leaf takes the file's, and is owed the handshake; what is already here —
// threads, messages, files — is left as it is and counted as such.
func TestAnImportIntoTheSameIdentityMergesAndNeverReplacesAHeldPin(t *testing.T) {
	ctx := context.Background()
	raw, _ := fs.ReadFile(exportcorpus.FS, "cases.json")
	var idx exportcorpus.Index
	must(t, json.Unmarshal(raw, &idx))
	now, _ := time.Parse(time.RFC3339, idx.Now)
	valid, err := fs.ReadFile(exportcorpus.FS, "valid-export.zip")
	must(t, err)
	contents, err := pactidentity.ReadExportZip(zipReader(t, valid), idx.Owner, now, ImportCeiling)
	must(t, err)
	var pinnedRow pactidentity.ContactRow
	var others []pactidentity.ContactRow
	for _, r := range contents.Contacts {
		if r.Leaf != nil && pinnedRow.Root == "" {
			pinnedRow = r
		} else {
			others = append(others, r)
		}
	}
	if pinnedRow.Root == "" || len(others) == 0 {
		t.Fatal("the corpus's valid export must hold a row whose leaf pins, and others")
	}

	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			e := newEnv(t, eng.open)
			a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
			must(t, err)
			must(t, e.st.SetAccountRoot(ctx, a.ID, idx.Owner, nil))
			// Held WITH a leaf, at another address: the held pin stands.
			heldWithLeaf := others[0]
			_, err = e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: heldWithLeaf.Root, SPKI: []byte("held-spki"), Status: "active",
				Endpoint: "https://held.example/a/x/mcp", Leaf: []byte("held-leaf")})
			must(t, err)
			// Held with NO leaf: the file's validated pin fills it.
			_, err = e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: pinnedRow.Root, Status: "active", Endpoint: pinnedRow.Endpoint})
			must(t, err)

			p, res, err := importFile(t, e, valid, "alina", now)
			if err != nil {
				t.Fatal(err)
			}
			if p.New {
				t.Fatal("an import into the identity already here must merge, not create")
			}
			kept := false
			for _, root := range p.Keep {
				kept = kept || root == heldWithLeaf.Root
			}
			if !kept || len(p.Conflicts) == 0 {
				t.Fatalf("the held pin must be kept and the difference shown: keep=%v conflicts=%+v", p.Keep, p.Conflicts)
			}
			c, err := e.st.GetContact(ctx, a.ID, heldWithLeaf.Root)
			must(t, err)
			if c.Endpoint != "https://held.example/a/x/mcp" || string(c.Leaf) != "held-leaf" || c.HandshakeDue {
				t.Fatalf("a held pin was changed by a file: %+v", c)
			}
			c, err = e.st.GetContact(ctx, a.ID, pinnedRow.Root)
			must(t, err)
			if pactidentity.B64url(c.Leaf) != *pinnedRow.Leaf || len(c.SPKI) == 0 || !c.HandshakeDue {
				t.Fatalf("a contact held with no leaf must take the file's validated pin and be owed the handshake: %+v", c)
			}
			if res.Contacts != len(contents.Contacts)-1 {
				t.Fatalf("wrote %d contacts, want every row but the kept one (%d)", res.Contacts, len(contents.Contacts)-1)
			}
			// The same file again: nothing new, and it says so.
			_, again, err := importFile(t, e, valid, "alina", now)
			if err != nil {
				t.Fatal(err)
			}
			if again.Contacts != 0 || again.Threads != 0 || again.Messages != 0 || again.AlreadyHere != len(contents.Threads)+len(contents.Messages) {
				t.Fatalf("a second import of the same file: %+v", again)
			}
		})
	}
}

// Out of one node and into another, on both engines: what the file carries arrives as it was, a
// file message as a file message, and what it does not carry is not invented.
func TestARoundTripKeepsWhatAnExportCarries(t *testing.T) {
	ctx := context.Background()
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			src := newEnv(t, eng.open)
			s := seed(t, src)
			file, _ := exportOf(t, src, "alina")
			dst := newEnv(t, eng.open)
			p, res, err := importFile(t, dst, file, "alina", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if !p.New || res.Contacts != 1 || res.Threads != 1 || res.Messages != 4 || res.Media != 1 {
				t.Fatalf("imported %+v (new=%v)", res, p.New)
			}
			a, err := dst.st.GetAccountBySlug(ctx, "alina")
			must(t, err)
			if a.RootFingerprint != s.me.Fpr || a.DisplayName != "Alina Rao" {
				t.Fatalf("the identity arrived as %+v", a)
			}
			c, err := dst.st.GetContact(ctx, a.ID, s.peer.Fpr)
			must(t, err)
			if c.Status != "active" || !c.EverActive || c.Petname != "B, from the conference" || c.DisplayName != "Bharat Mehta" ||
				c.Endpoint != s.host.Endpoint || !bytes.Equal(c.Leaf, s.host.LeafDER) || !bytes.Equal(c.SPKI, s.host.Key.Public.SPKI) ||
				!bytes.Equal(c.RootCert, s.peer.RootDER) || strings.Join(c.Permissions, " ") != "message.media message.text" {
				t.Fatalf("the contact arrived as %+v", c)
			}
			// What the format leaves out stays out: the trust flag is this host's default, no card, no invite.
			if c.TrustFlag != "messages_only" || c.Card != "" || c.InviteID != "" || c.ChainSentKid != "" {
				t.Fatalf("the contact arrived with host state: trust=%q card=%d invite=%q chain_sent=%q", c.TrustFlag, len(c.Card), c.InviteID, c.ChainSentKid)
			}
			if _, err := dst.st.GetContact(ctx, a.ID, s.strangerID); err == nil {
				t.Fatal("a stranger's request travelled")
			}
			msgs, err := dst.st.ListMessagesByThread(ctx, a.ID, "t1")
			must(t, err)
			byID := map[string]store.Message{}
			for _, m := range msgs {
				byID[m.ID] = m
			}
			var meta messaging.MediaMeta
			if m := byID["m2"]; m.Kind != "media" || json.Unmarshal([]byte(m.Body), &meta) != nil || meta.Hash != s.mediaHash || meta.Filename != "whiteboard.png" || m.ReplyTo != "msg-1" {
				t.Fatalf("the file message arrived as %+v", m)
			}
			if data, err := dst.blobs.Get(s.mediaHash); err != nil || string(data) != "a photograph of a whiteboard" {
				t.Fatalf("the file: %q %v", data, err)
			}
			if b, err := dst.st.GetBlob(ctx, a.ID, s.mediaHash); err != nil || b.Mime != "image/png" {
				t.Fatalf("the file's record: %+v %v", b, err)
			}
			if m := byID["m3"]; m.Kind != "text" || m.Body != "https://files.example/slides.pdf" {
				t.Fatalf("the link message arrived as %+v", m)
			}
			// An undelivered message was the old host's to deliver: it arrives failed, unscheduled.
			if m := byID["m4"]; m.Status != "failed" || m.Attempts != 0 || m.NextAttemptAt != 0 || m.ExpiresAt != 0 {
				t.Fatalf("the undelivered message arrived as %+v", m)
			}
		})
	}
}

// An export that cannot be what it claims is refused by name, and leaves no file behind a caller
// could mistake for one.
func TestAnExportRefusesWhatItCannotCarry(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	var buf bytes.Buffer
	if _, err := Export(ctx, e.st, e.blobs, &buf, "nobody", "t", exportedAt); !errors.Is(err, ErrRefused) {
		t.Fatalf("an identity that is not here: %v", err)
	}
	_, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "unrooted", DisplayName: "Not Yet", Algo: "p256"})
	must(t, err)
	if _, err := Export(ctx, e.st, e.blobs, &buf, "unrooted", "t", exportedAt); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "never been issued a certificate") {
		t.Fatalf("an identity with no root: %v", err)
	}
	// A file on record and not on disk is refused naming the message, not left out.
	must(t, e.blobs.Remove(s.mediaHash))
	if _, err := Export(ctx, e.st, e.blobs, &buf, "alina", "t", exportedAt); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "message m2 names file "+s.mediaHash) {
		t.Fatalf("a file this node no longer holds: %v", err)
	}
}

// The same corpus imported into a slug that is NOT here — a move onto a fresh host, which is how
// most imports go. The owner then comes from the file, so every refusal but the owner's own must be
// the same words, and nothing is written; wrong-owner has no meaning for a new slug.
func TestTheCorpusIntoANewSlugIsRefusedInTheSameWords(t *testing.T) {
	raw, err := fs.ReadFile(exportcorpus.FS, "cases.json")
	must(t, err)
	var idx exportcorpus.Index
	must(t, json.Unmarshal(raw, &idx))
	now, err := time.Parse(time.RFC3339, idx.Now)
	must(t, err)
	checked := 0
	for _, c := range idx.Cases {
		if c.Accept != nil || c.File == "wrong-owner.zip" {
			continue
		}
		t.Run(c.File, func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t, sqliteStore)
			b, err := fs.ReadFile(exportcorpus.FS, c.File)
			must(t, err)
			_, _, err = importFile(t, e, b, "fresh", now)
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("%s was not refused: %v", c.File, err)
			}
			why := strings.TrimPrefix(err.Error(), ErrRefused.Error()+": ")
			switch {
			case c.Refusal != "" && why != c.Refusal:
				t.Fatalf("%s: refused with\n  %q\nwant\n  %q", c.File, why, c.Refusal)
			case c.RefusalPrefix != "" && !strings.HasPrefix(why, c.RefusalPrefix):
				t.Fatalf("%s: refused with %q, want it to begin %q", c.File, why, c.RefusalPrefix)
			}
			if accts, _ := e.st.ListAccounts(ctx); len(accts) != 0 {
				t.Fatalf("%s was refused and made %d identity", c.File, len(accts))
			}
			checked++
		})
	}
	if checked < 30 {
		t.Fatalf("only %d hostile cases ran into a new slug", checked)
	}
}

// A stranger's request this host holds (pending_in), and a file that says the same root is a
// contact: the held row stands. The person decides the request here, as any other; the file does
// not accept it for them, and the row is not marked as owed a handshake.
func TestAHeldRequestIsKeptWhenTheFileNamesTheSameRoot(t *testing.T) {
	ctx := context.Background()
	raw, _ := fs.ReadFile(exportcorpus.FS, "cases.json")
	var idx exportcorpus.Index
	must(t, json.Unmarshal(raw, &idx))
	now, _ := time.Parse(time.RFC3339, idx.Now)
	valid, err := fs.ReadFile(exportcorpus.FS, "valid-export.zip")
	must(t, err)
	contents, err := pactidentity.ReadExportZip(zipReader(t, valid), idx.Owner, now, ImportCeiling)
	must(t, err)
	var row pactidentity.ContactRow
	for _, r := range contents.Contacts {
		if r.Leaf != nil {
			row = r
		}
	}
	if row.Root == "" {
		t.Fatal("the corpus's valid export must hold a row whose leaf pins")
	}
	e := newEnv(t, sqliteStore)
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	must(t, err)
	must(t, e.st.SetAccountRoot(ctx, a.ID, idx.Owner, nil))
	_, err = e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: row.Root, SPKI: []byte("req-spki"), Status: "pending_in",
		Endpoint: "https://asker.example/a/x/mcp", Leaf: []byte("request-leaf"), PinnedAt: 5})
	must(t, err)

	p, _, err := importFile(t, e, valid, "alina", now)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, root := range p.Keep {
		kept = kept || root == row.Root
	}
	if !kept {
		t.Fatalf("the held request was not kept: keep=%v", p.Keep)
	}
	c, err := e.st.GetContact(ctx, a.ID, row.Root)
	must(t, err)
	if c.Status != "pending_in" || string(c.Leaf) != "request-leaf" || c.Endpoint != "https://asker.example/a/x/mcp" || c.HandshakeDue {
		t.Fatalf("a held request was changed by a file: %+v", c)
	}
}

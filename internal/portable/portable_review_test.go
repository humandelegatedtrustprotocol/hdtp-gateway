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
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
	"github.com/humandelegatedtrustprotocol/hdtp-identity/go/exportcorpus"
)

// The review of 2026-09-28 on export and import.

// corpusValid is hdtp-identity's valid export, its owner, and the corpus's clock.
func corpusValid(t *testing.T) ([]byte, string, time.Time) {
	t.Helper()
	raw, _ := fs.ReadFile(exportcorpus.FS, "cases.json")
	var idx exportcorpus.Index
	must(t, json.Unmarshal(raw, &idx))
	now, _ := time.Parse(time.RFC3339, idx.Now)
	valid, err := fs.ReadFile(exportcorpus.FS, "valid-export.zip")
	must(t, err)
	return valid, idx.Owner, now
}

// rezip rewrites one member of a zip.
func rezip(t *testing.T, b []byte, name string, edit func([]byte) []byte) []byte {
	t.Helper()
	zr := zipReader(t, b)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		rc, err := f.Open()
		must(t, err)
		body, err := io.ReadAll(rc)
		must(t, err)
		rc.Close()
		if f.Name == name {
			body = edit(body)
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method, Modified: f.Modified})
		must(t, err)
		_, err = w.Write(body)
		must(t, err)
	}
	must(t, zw.Close())
	return out.Bytes()
}

// Coordinator item 5. Thread ids are an account's own, and a file names its threads by id: into an
// identity already here, a file thread `t` of contact Y met this identity's thread `t` of contact
// X, was left as it was, and Y's messages were written into X's thread. It is refused, and the
// review says so before anything is written.
func TestAFileThreadIsNotMergedIntoAnotherContactsThread(t *testing.T) {
	ctx := context.Background()
	valid, owner, now := corpusValid(t)
	contents, err := hdtpidentity.ReadExportZip(zipReader(t, valid), owner, now, ImportCeiling)
	must(t, err)
	if len(contents.Threads) == 0 {
		t.Fatal("the corpus's valid export must hold a thread")
	}
	th := contents.Threads[0]
	e := newEnv(t, sqliteStore)
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	must(t, err)
	must(t, e.st.SetAccountRoot(ctx, a.ID, owner, nil))
	must(t, e.st.InsertThread(ctx, store.Thread{ID: th.ID, AccountID: a.ID, ContactFpr: "sha256:somebody-else", Topic: "ours", CreatedAt: 1, LastAt: 1}))
	_, err = Read(ctx, e.st, zipReader(t, valid), "alina", now)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "thread "+th.ID) {
		t.Fatalf("a file thread over another contact's thread: %v", err)
	}
	if got, _ := e.st.ListMessagesByThread(ctx, a.ID, th.ID); len(got) != 0 {
		t.Fatalf("messages were written into the other contact's thread: %d", len(got))
	}
}

// Coordinator item 5, the same class for messages. A message's id is unique on the node, so a file
// message whose id another message holds - another identity's, here - was not written and was
// counted as "already here".
func TestAFileMessageWhoseIDIsTakenIsRefused(t *testing.T) {
	ctx := context.Background()
	valid, owner, now := corpusValid(t)
	contents, err := hdtpidentity.ReadExportZip(zipReader(t, valid), owner, now, ImportCeiling)
	must(t, err)
	m := contents.Messages[0]
	e := newEnv(t, sqliteStore)
	other, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	must(t, err)
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "their-thread", AccountID: other.ID, ContactFpr: "sha256:x", CreatedAt: 1, LastAt: 1}))
	must(t, e.st.InsertMessage(ctx, store.Message{ID: m.ID, AccountID: other.ID, ContactFpr: "sha256:x", MsgID: "theirs", ThreadID: "their-thread",
		Direction: "in", Sender: "human", Kind: "text", Body: "somebody else's", Status: "delivered", CreatedAt: 1}))
	_, res, err := importFile(t, e, valid, "moved-here", now)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "message "+m.ID) {
		t.Fatalf("a file message whose id is taken: %v %+v", err, res)
	}
	if _, err := e.st.GetAccountBySlug(ctx, "moved-here"); err == nil {
		t.Fatal("the refused import made the identity")
	}
}

// M6. The import made the account with the file's owner_name and without the check every other
// door makes: a display name is one line of the account's card, and a control character in it is
// refused (identity.ValidDisplayName). The review refuses it before anything is written.
func TestAnOwnerNameWithAControlCharacterIsRefusedAtTheReview(t *testing.T) {
	ctx := context.Background()
	valid, _, now := corpusValid(t)
	bad := rezip(t, valid, "manifest.json", func(b []byte) []byte {
		var m map[string]any
		must(t, json.Unmarshal(b, &m))
		m["owner_name"] = "Alina\u0085ORG:Somebody Else"
		out, err := json.Marshal(m)
		must(t, err)
		return out
	})
	e := newEnv(t, sqliteStore)
	_, err := Read(ctx, e.st, zipReader(t, bad), "moved-here", now)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("an owner_name with a control character: %v", err)
	}
}

// L10. An import's counts are what it wrote: a file already here is counted as already here, not as
// written, and a contact held with no leaf that the file's pin fills is a fill, shown and counted
// as one, not a new contact.
func TestAnImportCountsWhatItWrote(t *testing.T) {
	ctx := context.Background()
	src := newEnv(t, sqliteStore)
	s := seed(t, src)
	file, _ := exportOf(t, src, "alina")
	e := newEnv(t, sqliteStore)
	// The same identity is here, holding the contact with no leaf.
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	must(t, err)
	must(t, e.st.SetAccountRoot(ctx, a.ID, s.me.Fpr, nil))
	_, err = e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: s.peer.Fpr, Status: "active", Endpoint: s.host.Endpoint})
	must(t, err)
	p, res, err := importFile(t, e, file, "alina", time.Now())
	must(t, err)
	if len(p.Fill) != 1 || p.Fill[0] != s.peer.Fpr || res.Contacts != 0 || res.PinsFilled != 1 || res.Media != 1 {
		t.Fatalf("a first import: fill=%v %+v", p.Fill, res)
	}
	_, again, err := importFile(t, e, file, "alina", time.Now())
	must(t, err)
	if again.Media != 0 || again.Threads != 0 || again.Messages != 0 || again.AlreadyHere != 1+4+1 {
		t.Fatalf("the same file again: %+v, want nothing written and a thread, four messages and a file already here", again)
	}
}

// L11. An export that leaves a conversation out says which and why, truly: a request not yet
// decided, or a root that was never a contact. A thread naming a root with no row and no record of
// being a contact is the second (HDTP §9.2); a former contact's travels (removed_test.go).
func TestAnExportSaysTrulyWhyItLeftAConversationOut(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	must(t, e.st.InsertThread(ctx, store.Thread{ID: "t-gone", AccountID: s.accountID, ContactFpr: "sha256:gone", Topic: "old", CreatedAt: 1790000040, LastAt: 1790000040}))
	_, res := exportOf(t, e, "alina")
	joined := strings.Join(res.LeftOut, "\n")
	if !strings.Contains(joined, "thread t-stranger: 1 message(s) with "+s.strangerID+", whose request is not yet decided") ||
		!strings.Contains(joined, "thread t-gone: 0 message(s) with sha256:gone, who was never a contact") {
		t.Fatalf("left out:\n%s", joined)
	}
}

// Coordinator item 8. A message waiting for its human (the legacy queued_for_human) travels as
// `queued`, as the cloud's exporter writes it; it had been written `delivered`. An inbound message
// arrives at the importing host as delivered, whatever the file says of it: it reached the host
// that exported it.
func TestAMessageWaitingForItsHumanTravelsQueued(t *testing.T) {
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	file, _ := exportOf(t, e, "alina")
	got, err := hdtpidentity.ReadExportZip(zipReader(t, file), s.me.Fpr, time.Now(), ImportCeiling)
	must(t, err)
	for _, m := range got.Messages {
		if m.ID == "m3" && m.Status != "queued" {
			t.Fatalf("a message waiting for its human travels as %q", m.Status)
		}
	}
	into := newEnv(t, sqliteStore)
	_, _, err = importFile(t, into, file, "alina", time.Now())
	must(t, err)
	a, _ := into.st.GetAccountBySlug(context.Background(), "alina")
	msgs, _ := into.st.ListMessagesByThread(context.Background(), a.ID, "t1")
	for _, m := range msgs {
		if m.ID == "m3" && m.Status != "delivered" {
			t.Fatalf("an inbound message arrived as %q", m.Status)
		}
	}
}

// L12. An export over what BatonDeck takes back in is written, and says so, naming the limits:
// other hosts may take it, so it is a warning and never a refusal (HDTP §9.2, Ceilings: a host's own import
// ceilings never refuse an export). The seed holds one thread: at the ceiling nothing is said, one
// over it is.
func TestAnExportOverTheCloudsCeilingsSaysSo(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	bulk := func(from, to int) {
		must(t, e.st.Atomically(ctx, func(tx store.Store) error {
			for i := from; i < to; i++ {
				if err := tx.InsertThread(ctx, store.Thread{ID: fmt.Sprintf("bulk-%d", i), AccountID: s.accountID, ContactFpr: s.peer.Fpr, CreatedAt: 1790000100, LastAt: 1790000100}); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	bulk(0, cloudThreads-1)
	file, res := exportOf(t, e, "alina")
	if w := CloudCeilings(zipReader(t, file), uint64(len(file))); len(w) != 0 || res.Threads != cloudThreads {
		t.Fatalf("an export at the ceiling warned: %v (threads %d)", w, res.Threads)
	}
	bulk(cloudThreads-1, cloudThreads)
	file, res = exportOf(t, e, "alina")
	warnings := CloudCeilings(zipReader(t, file), uint64(len(file)))
	want := fmt.Sprintf("%d threads, over BatonDeck's %d", cloudThreads+1, cloudThreads)
	if len(warnings) != 1 || warnings[0] != want || res.Threads != cloudThreads+1 {
		t.Fatalf("the warnings: %v (threads %d), want [%s]", warnings, res.Threads, want)
	}
	small := newEnv(t, sqliteStore)
	seed(t, small)
	file, _ = exportOf(t, small, "alina")
	if w := CloudCeilings(zipReader(t, file), uint64(len(file))); len(w) != 0 {
		t.Fatalf("a small export warned: %v", w)
	}
}

// ceilingZip is a zip of the members given, each a name and its bytes; a member whose bytes are nil
// is written stored and empty with the size stated, since the files are counted by what their
// directory entries state.
func ceilingZip(t *testing.T, members []ceilingMember) *zip.Reader {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, m := range members {
		if m.body == nil {
			_, err := zw.CreateRaw(&zip.FileHeader{Name: m.name, Method: zip.Store, CompressedSize64: 0, UncompressedSize64: m.stated})
			must(t, err)
			continue
		}
		w, err := zw.Create(m.name)
		must(t, err)
		_, err = w.Write(m.body)
		must(t, err)
	}
	must(t, zw.Close())
	return zipReader(t, b.Bytes())
}

type ceilingMember struct {
	name   string
	body   []byte
	stated uint64
}

// csvOf is a CSV member of a header and n rows, padded with a last column to exactly size bytes
// when size is not 0.
func csvOf(t *testing.T, rows, size int) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString("a,b\n")
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&b, "%d,\n", i)
	}
	if size != 0 {
		if b.Len() > size {
			t.Fatalf("%d rows do not fit in %d bytes", rows, size)
		}
		b.WriteString(strings.Repeat("x", size-b.Len()))
	}
	return []byte(b.String())
}

// messagesOf is messages.jsonl of n lines whose ids (id and msg_id; reply_to on the first line)
// carry exactly chars characters between them.
func messagesOf(t *testing.T, lines, chars int) []byte {
	t.Helper()
	per := chars / lines
	var b bytes.Buffer
	for i := 0; i < lines; i++ {
		n := per
		if i == 0 {
			n += chars - per*lines
		}
		id := strings.Repeat("i", n/2)
		msgID := strings.Repeat("m", n-n/2-1)
		line, err := json.Marshal(map[string]any{"id": id, "msg_id": msgID, "reply_to": "r"})
		must(t, err)
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// mediaOf is n media files stating total bytes between them.
func mediaOf(n int, total uint64) []ceilingMember {
	out := make([]ceilingMember, n)
	for i := range out {
		out[i] = ceilingMember{name: fmt.Sprintf("media/%064x", i), stated: total / uint64(n)}
	}
	out[0].stated += total - total/uint64(n)*uint64(n)
	return out
}

// Each of BatonDeck's ceilings, at its limit and one over it: at the limit nothing is said, one
// over it exactly one warning, naming the number and the limit.
func TestTheCloudsCeilingsAtTheirBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		members func(n int) []ceilingMember
		zip     func(n int) uint64
		limit   int
		what    string
	}{
		{"contacts", func(n int) []ceilingMember { return []ceilingMember{{name: "contacts.csv", body: csvOf(t, n, 0)}} }, nil, cloudContacts, "contacts"},
		{"contacts.csv bytes", func(n int) []ceilingMember { return []ceilingMember{{name: "contacts.csv", body: csvOf(t, 1, n)}} }, nil, cloudContactsCSVBytes, "bytes of contacts.csv"},
		{"threads", func(n int) []ceilingMember { return []ceilingMember{{name: "threads.csv", body: csvOf(t, n, 0)}} }, nil, cloudThreads, "threads"},
		{"threads.csv bytes", func(n int) []ceilingMember { return []ceilingMember{{name: "threads.csv", body: csvOf(t, 1, n)}} }, nil, cloudThreadsCSVBytes, "bytes of threads.csv"},
		{"message lines", func(n int) []ceilingMember {
			return []ceilingMember{{name: "messages.jsonl", body: messagesOf(t, n, 3*n)}}
		}, nil, cloudMessageLines, "message lines"},
		{"message id characters", func(n int) []ceilingMember {
			return []ceilingMember{{name: "messages.jsonl", body: messagesOf(t, 1000, n)}}
		}, nil, cloudIDCharacters, "characters of message ids (id, msg_id, reply_to)"},
		{"files", func(n int) []ceilingMember { return mediaOf(n, uint64(n)) }, nil, cloudMediaFiles, "files"},
		{"bytes of files", func(n int) []ceilingMember { return mediaOf(10, uint64(n)) }, nil, cloudMediaBytes, "bytes of files"},
		{"bytes of zip", func(int) []ceilingMember { return nil }, func(n int) uint64 { return uint64(n) }, cloudZipBytes, "bytes of zip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, n := range []int{c.limit, c.limit + 1} {
				var size uint64
				if c.zip != nil {
					size = c.zip(n)
				}
				got := CloudCeilings(ceilingZip(t, c.members(n)), size)
				var want []string
				if n > c.limit {
					want = []string{fmt.Sprintf("%d %s, over BatonDeck's %d", n, c.what, c.limit)}
				}
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("at %d: %q, want %q", n, got, want)
				}
			}
		})
	}
}

// A file is counted by its name as the cloud counts it: media/ and 64 lowercase hex. The directory
// entry media/ and any other name are not files.
func TestOnlyAMediaNameIsAFile(t *testing.T) {
	members := mediaOf(cloudMediaFiles, cloudMediaFiles)
	members = append(members, ceilingMember{name: "media/", stated: 0}, ceilingMember{name: "media/" + strings.Repeat("A", 64), stated: 1}, ceilingMember{name: "media/short", stated: 1})
	if w := CloudCeilings(ceilingZip(t, members), 0); len(w) != 0 {
		t.Fatalf("a name that is not a file was counted: %v", w)
	}
}

// The cloud derives its central directory bounds from its files (limits.ts DIRECTORY_LIMITS): the
// files and the five members that are not a file, each record at most 46 bytes, the longest name
// (media/ and a sha256 in hex) and 32 bytes of extra fields. The node's copies are held to it.
func TestTheCloudsDirectoryBounds(t *testing.T) {
	if cloudZipEntries != cloudMediaFiles+5 {
		t.Fatalf("entries %d, files %d", cloudZipEntries, cloudMediaFiles)
	}
	if cloudDirectoryBytes != cloudZipEntries*(46+len("media/")+64+32) {
		t.Fatalf("directory bytes %d, entries %d", cloudDirectoryBytes, cloudZipEntries)
	}
}

// L12, the importer's side. What an import holds in memory follows messages.jsonl, the one member
// read whole, and is bounded by ImportMessagesCeiling, checked against the member's declared size
// before a byte of it is read. The allocation per byte is measured here, at N and 4N messages, and
// the ceiling is held to it: at most 16 bytes allocated per byte (11.4-11.5 measured), so the
// ceiling's worst case stays under 2 GiB.
func TestAnImportsMemoryFollowsItsMessages(t *testing.T) {
	per := func(n int) float64 {
		owner := testidWallet(t, "Probe")
		at := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
		root := testidWallet(t, "C")
		in := hdtpidentity.ExportInput{Owner: owner, OwnerName: "P", Tool: "probe", ExportedAt: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
			Contacts: []hdtpidentity.ContactRow{{Root: root, Endpoint: "https://c.example/a/c/mcp", Status: "active", WasActive: true, Permissions: []string{}, TheirPermissions: []string{}, Added: at}},
			Threads:  []hdtpidentity.ThreadRow{{ID: "t", Contact: root, CreatedAt: at, LastAt: at}}, Media: []hdtpidentity.ExportMedia{}}
		body := strings.Repeat("x", 1000)
		for i := 0; i < n; i++ {
			id := fmt.Sprint(i)
			in.Messages = append(in.Messages, hdtpidentity.MessageRow{ID: "m" + id, Thread: "t", Contact: root, MsgID: "msg-" + id, Direction: "in",
				Sender: "human", Time: at, Body: body, Status: "delivered", Attachments: []hdtpidentity.Attachment{}})
		}
		var buf bytes.Buffer
		_, err := hdtpidentity.WriteExportZip(&buf, in, nil)
		must(t, err)
		var size uint64
		for _, f := range zipReader(t, buf.Bytes()).File {
			if f.Name == "messages.jsonl" {
				size = f.UncompressedSize64
			}
		}
		e := newEnv(t, sqliteStore)
		runtime.GC()
		defer debug.SetGCPercent(debug.SetGCPercent(-1))
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		p, err := Read(context.Background(), e.st, zipReader(t, buf.Bytes()), "probe", time.Now())
		must(t, err)
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(p)
		return float64(after.TotalAlloc-before.TotalAlloc) / float64(size)
	}
	small, large := per(2000), per(8000)
	t.Logf("allocated per byte of messages.jsonl: %.1f at 2,000 messages, %.1f at 8,000", small, large)
	for _, r := range []float64{small, large} {
		if r > 16 {
			t.Fatalf("an import allocates %.1f bytes per byte of messages.jsonl, over the 16 its ceiling is set by", r)
		}
	}
	if float64(ImportMessagesCeiling)*16 > 2<<30 {
		t.Fatalf("ImportMessagesCeiling %d allows over 2 GiB of allocation at 16 bytes per byte", ImportMessagesCeiling)
	}
	// A messages.jsonl that declares more than the ceiling is refused by that declaration, unread.
	valid, _, now := corpusValid(t)
	zr := zipReader(t, valid)
	for _, f := range zr.File {
		if f.Name == "messages.jsonl" {
			f.UncompressedSize64 = ImportMessagesCeiling + 1
		}
	}
	if _, err := Read(context.Background(), newEnv(t, sqliteStore).st, zr, "moved-here", now); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "reads into memory") {
		t.Fatalf("a messages.jsonl over the ceiling: %v", err)
	}
}

func testidWallet(t *testing.T, cn string) string { return testid.NewWallet(t, cn).Fpr }

// H3, the read-back. `export` reads its file back as an importer would before it reports it; a
// file that does not read — here one member rewritten after it was written, so its hash is not the
// manifest's — is refused, and the verb removes it.
func TestAFileThatDoesNotReadBackIsRefused(t *testing.T) {
	e := newEnv(t, sqliteStore)
	s := seed(t, e)
	file, _ := exportOf(t, e, "alina")
	must(t, CheckWritten(zipReader(t, file), s.me.Fpr, time.Now()))
	bad := rezip(t, file, "threads.csv", func(b []byte) []byte {
		return append(b, []byte("t9,"+s.peer.Fpr+",x,2026-01-01T00:00:00Z,2026-01-01T00:00:00Z\n")...)
	})
	if err := CheckWritten(zipReader(t, bad), s.me.Fpr, time.Now()); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not read back as an export") {
		t.Fatalf("a file that does not read: %v", err)
	}
}

// hdtp-identity 0.3.3's export_merge keeps a contact held here blocked, and the permissions held
// here, whatever the file says, and reports each difference as a conflict; the review shows them.
func TestAMergeKeepsAHeldBlockAndSaysSo(t *testing.T) {
	ctx := context.Background()
	src := newEnv(t, sqliteStore)
	s := seed(t, src)
	file, _ := exportOf(t, src, "alina")
	e := newEnv(t, sqliteStore)
	a, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alina", DisplayName: "Alina", Algo: "p256"})
	must(t, err)
	must(t, e.st.SetAccountRoot(ctx, a.ID, s.me.Fpr, nil))
	_, err = e.st.InsertContact(ctx, store.Contact{AccountID: a.ID, Fingerprint: s.peer.Fpr, SPKI: s.host.Key.Public().SPKI, Status: "blocked",
		Permissions: []string{"message.text"}, Endpoint: s.host.Endpoint, Leaf: s.host.LeafDER})
	must(t, err)
	p, err := Read(ctx, e.st, zipReader(t, file), "alina", time.Now())
	must(t, err)
	fields := map[string]bool{}
	for _, c := range p.Conflicts {
		fields[c.Field] = c.Root == s.peer.Fpr
	}
	if !fields["status"] || !fields["permissions"] {
		t.Fatalf("the review's conflicts: %+v", p.Conflicts)
	}
	_, _, err = importFile(t, e, file, "alina", time.Now())
	must(t, err)
	c, err := e.st.GetContact(ctx, a.ID, s.peer.Fpr)
	must(t, err)
	if c.Status != "blocked" || strings.Join(c.Permissions, " ") != "message.text" {
		t.Fatalf("the held contact after the merge: %s %v", c.Status, c.Permissions)
	}
}

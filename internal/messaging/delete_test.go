package messaging

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// deleteEnv is a sweepEnv whose Service removes files, as the portal's and the owner MCP's do.
func deleteEnv(t *testing.T) *sweepEnv {
	e := newSweepEnv(t)
	e.svc.Blobs = e.blobs
	return e
}

func (e *sweepEnv) inline(t *testing.T, contact, threadID, msgID string, data []byte) (string, string) {
	t.Helper()
	r, err := e.media.ReceiveInline(context.Background(), e.svc, e.acct, contact,
		Input{Origin: OriginPeer, MsgID: msgID, ThreadID: threadID, Sender: SenderHuman}, "f.bin", "application/octet-stream", data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.st.GetBlob(context.Background(), e.acct, hashOf(data))
	if err != nil {
		t.Fatal(err)
	}
	return r.ThreadID, b.Hash
}

func hashOf(data []byte) string {
	tmp, _ := os.MkdirTemp("", "h")
	defer os.RemoveAll(tmp)
	h, _ := BlobDir{Root: tmp}.Put(data)
	return h
}

func (e *sweepEnv) fileExists(hash string) bool {
	_, err := e.blobs.Get(hash)
	return err == nil
}

// Deleting a conversation removes the thread, every message of it, its change-log rows and the
// files only it named; the same contact's other thread, a file another thread still names, and the
// idempotency records stay.
func TestDeletingAConversationRemovesItAndOnlyIt(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	gone, onlyHere := e.inline(t, "sha256:peer", "", "m1", []byte("only in the deleted thread"))
	_, shared := e.inline(t, "sha256:peer", gone, "m2", []byte("in both threads"))
	if _, err := e.svc.Record(ctx, e.acct, "sha256:peer", DirOut, Input{Origin: OriginPortal, MsgID: "o1", ThreadID: gone, Text: "pending"}); err != nil {
		t.Fatal(err)
	}
	kept, _ := e.inline(t, "sha256:peer", "", "m3", []byte("in both threads"))
	if _, err := e.st.AppendChange(ctx, store.Change{AccountID: e.acct, Kind: "message", ThreadID: gone, At: 1}); err != nil {
		t.Fatal(err)
	}

	out, err := e.svc.DeleteThread(ctx, e.acct, gone)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" || out.ThreadID != gone || out.Messages != 3 || out.Files != 1 || out.Contact != "sha256:peer" {
		t.Fatalf("answer = %+v; want deleted, 3 messages, 1 file", out)
	}
	if _, err := e.st.GetThread(ctx, e.acct, gone); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the thread is still there: %v", err)
	}
	if left, _ := e.st.ListMessagesByThread(ctx, e.acct, gone); len(left) != 0 {
		t.Fatalf("%d messages of the deleted thread remain", len(left))
	}
	if pending, _ := e.st.ListPendingOutbound(ctx, 10); len(pending) != 0 {
		t.Fatalf("the deleted thread's outbound message would still be retried: %+v", pending)
	}
	if changes, _ := e.st.AccountChangesAfter(ctx, e.acct, 0, 100); len(changes) != 0 {
		for _, c := range changes {
			if c.ThreadID == gone {
				t.Fatalf("a change row still names the deleted thread: %+v", c)
			}
		}
	}
	if _, err := e.st.GetBlob(ctx, e.acct, onlyHere); err == nil || e.fileExists(onlyHere) {
		t.Fatalf("the file only the deleted thread named is still held (record err %v, file %v)", err, e.fileExists(onlyHere))
	}
	if _, err := e.st.GetBlob(ctx, e.acct, shared); err != nil || !e.fileExists(shared) {
		t.Fatalf("a file another thread still names went: %v", err)
	}
	if _, err := e.st.GetThread(ctx, e.acct, kept); err != nil {
		t.Fatalf("the other thread went: %v", err)
	}
}

// A file another ACCOUNT names stays on disk when this account's record of it goes: the store is
// content-addressed and shared.
func TestDeletingAConversationKeepsAFileAnotherAccountNames(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	data := []byte("both accounts hold these bytes")
	thread, hash := e.inline(t, "sha256:peer", "", "m1", data)
	other, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.media.ReceiveInline(ctx, e.svc, other.ID, "sha256:peer", Input{Origin: OriginPeer, MsgID: "x1", Sender: SenderHuman}, "f", "text/plain", data); err != nil {
		t.Fatal(err)
	}
	out, err := e.svc.DeleteThread(ctx, e.acct, thread)
	if err != nil || out.Files != 1 {
		t.Fatalf("DeleteThread = %+v, %v; want this account's one record collected", out, err)
	}
	if !e.fileExists(hash) {
		t.Fatal("the file went while another account still names it")
	}
}

// The refusals: an empty id, a thread the account does not hold, another account's thread.
func TestDeletingAConversationRefusesWhatIsNotThere(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	if _, err := e.svc.DeleteThread(ctx, e.acct, ""); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("empty id: %v, want ErrBadRequest", err)
	}
	if _, err := e.svc.DeleteThread(ctx, e.acct, "no-such-thread"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown thread: %v, want ErrNotFound", err)
	}
	other, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	r, err := e.svc.Record(ctx, other.ID, "sha256:peer", DirIn, Input{Origin: OriginPeer, MsgID: "x", Text: "theirs", Sender: SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeleteThread(ctx, e.acct, r.ThreadID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another account's thread: %v, want ErrNotFound", err)
	}
	if _, err := e.st.GetThread(ctx, other.ID, r.ThreadID); err != nil {
		t.Fatalf("another account's thread went: %v", err)
	}
}

// deletingStore deletes a thread at the moment a message is about to be written into it: the
// window between record's read of the thread and its writes.
type deletingStore struct {
	store.Store
	svc          *Service
	acct, thread string
	fired        bool
}

func (d *deletingStore) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	if !d.fired {
		d.fired = true
		if _, err := d.svc.DeleteThread(ctx, d.acct, d.thread); err != nil {
			return err
		}
	}
	return d.Store.Atomically(ctx, fn)
}

// A conversation deleted between record's read of the thread and its writes: the message starts
// the thread afresh, and is never left under a thread row that is gone, where no inbox and no
// export would find it.
func TestAMessageRecordedAsItsThreadIsDeletedStartsItAfresh(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	r, err := e.svc.Record(ctx, e.acct, "sha256:peer", DirIn, Input{Origin: OriginPeer, MsgID: "m1", Text: "first", Sender: SenderHuman})
	if err != nil {
		t.Fatal(err)
	}
	racing := &deletingStore{Store: e.st, svc: &Service{Store: e.st}, acct: e.acct, thread: r.ThreadID}
	svc := &Service{Store: racing}
	if _, err := svc.Record(ctx, e.acct, "sha256:peer", DirIn, Input{Origin: OriginPeer, MsgID: "m2", ThreadID: r.ThreadID, Text: "second", Sender: SenderHuman}); err != nil {
		t.Fatal(err)
	}
	if !racing.fired {
		t.Fatal("the deletion never ran: the test measured nothing")
	}
	if _, err := e.st.GetThread(ctx, e.acct, r.ThreadID); err != nil {
		t.Fatalf("the message was written under a thread that is gone: %v", err)
	}
	if msgs, _ := e.st.ListMessagesByThread(ctx, e.acct, r.ThreadID); len(msgs) != 1 || msgs[0].MsgID != "m2" {
		t.Fatalf("the thread holds %+v; want only the message that arrived after the deletion", msgs)
	}
}

// A link the owner fetched is recorded on its message: the message names the file, so deleting
// the conversation collects it, and retention counts it as in use while the message is kept.
func TestAFetchedFileBelongsToItsMessage(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("fetched-bytes"))
	}))
	defer srv.Close()
	e.media.isPrivate = func(net.IP) bool { return false }
	r, err := e.media.ReceiveURL(ctx, e.svc, e.acct, "sha256:peer", Input{Origin: OriginPeer, MsgID: "u1", Sender: SenderHuman}, "pic.png", "image/png", srv.URL+"/pic.png")
	if err != nil {
		t.Fatal(err)
	}
	msgs, _ := e.st.ListMessagesByThread(ctx, e.acct, r.ThreadID)
	if _, err := e.media.FetchMessage(ctx, e.acct, "no-such-message"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("fetching for a message that is not there: %v", err)
	}
	hash, err := e.media.FetchMessage(ctx, e.acct, msgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := e.st.GetMessage(ctx, e.acct, msgs[0].ID)
	if !strings.Contains(m.Body, `"hash":"`+hash+`"`) || !strings.Contains(m.Body, srv.URL) {
		t.Fatalf("the message does not name the file it fetched, or lost its link: %s", m.Body)
	}
	again, err := e.media.FetchMessage(ctx, e.acct, msgs[0].ID)
	if err != nil || again != hash {
		t.Fatalf("a second fetch = %q, %v; want the held file, fetched once", again, err)
	}
	// What retention reads to learn which files are in use names it now.
	if live, readable, err := referencedHashes(ctx, e.st, e.acct); err != nil || !readable || !live[hash] {
		t.Fatalf("retention does not see the fetched file as in use: %v %v %v", live, readable, err)
	}
	out, err := e.svc.DeleteThread(ctx, e.acct, r.ThreadID)
	if err != nil || out.Files != 1 {
		t.Fatalf("DeleteThread = %+v, %v; want the fetched file collected", out, err)
	}
	if e.fileExists(hash) {
		t.Fatal("the fetched file outlived its conversation")
	}
	if used, _ := e.st.SumBlobBytes(ctx, e.acct); used != 0 {
		t.Fatalf("the quota still counts %d bytes of a deleted conversation", used)
	}
}

// A message deleted while its link was being fetched leaves no file behind.
func TestAFileFetchedForAMessageDeletedMeanwhileIsCollected(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	var thread string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := e.svc.DeleteThread(context.Background(), e.acct, thread); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte("late bytes"))
	}))
	defer srv.Close()
	e.media.isPrivate = func(net.IP) bool { return false }
	r, err := e.media.ReceiveURL(ctx, e.svc, e.acct, "sha256:peer", Input{Origin: OriginPeer, MsgID: "u1", Sender: SenderHuman}, "x", "text/plain", srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	thread = r.ThreadID
	msgs, _ := e.st.ListMessagesByThread(ctx, e.acct, thread)
	if _, err := e.media.FetchMessage(ctx, e.acct, msgs[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FetchMessage = %v; want ErrNotFound for a message that went", err)
	}
	if blobs, _ := e.st.ListBlobs(ctx, e.acct); len(blobs) != 0 {
		t.Fatalf("a file nothing names was kept: %+v", blobs)
	}
	if n := countFiles(t, e.blobs.Root); n != 0 {
		t.Fatalf("%d files nothing names are on disk", n)
	}
}

func countFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// staleReadStore answers the collection's first read of the media bodies as it was, and records a
// message naming the same bytes in another thread before answering: the file is stored again after
// the read and before the file is judged.
type staleReadStore struct {
	store.Store
	arrive func()
	done   bool
}

func (s *staleReadStore) ListMediaBodies(ctx context.Context, accountID string) ([]string, error) {
	bodies, err := s.Store.ListMediaBodies(ctx, accountID)
	if !s.done {
		s.done = true
		s.arrive()
	}
	return bodies, err
}

// A file a deletion collects while the same bytes arrive in another thread stays: the file is
// judged under its lock, and asked again there whether a message names it.
func TestAFileStoredAgainWhileItsConversationIsDeletedStays(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	data := []byte("the same bytes, twice")
	thread, hash := e.inline(t, "sha256:peer", "", "m1", data)
	var again Result
	stale := &staleReadStore{Store: e.st, arrive: func() {
		r, err := e.media.ReceiveInline(ctx, e.svc, e.acct, "sha256:other", Input{Origin: OriginPeer, MsgID: "m2", Sender: SenderHuman}, "f.bin", "application/octet-stream", data)
		if err != nil {
			t.Error(err)
		}
		again = r
	}}
	svc := &Service{Store: stale, Blobs: e.blobs, Now: e.svc.Now}
	out, err := svc.DeleteThread(ctx, e.acct, thread)
	if err != nil {
		t.Fatal(err)
	}
	if !stale.done {
		t.Fatal("the second arrival never ran: the test measured nothing")
	}
	if out.Files != 0 {
		t.Fatalf("the deletion collected %d files; the bytes arrived again meanwhile", out.Files)
	}
	if _, err := e.st.GetBlob(ctx, e.acct, hash); err != nil || !e.fileExists(hash) {
		t.Fatalf("a file a new message names went (record %v, file %v)", err, e.fileExists(hash))
	}
	if msgs, _ := e.st.ListMessagesByThread(ctx, e.acct, again.ThreadID); len(msgs) != 1 || !strings.Contains(msgs[0].Body, hash) {
		t.Fatalf("the second message does not name the file: %+v", msgs)
	}
}

// Bytes a deletion has just taken are written anew by the next message that sends them: the record
// and the file come back together.
func TestBytesSentAgainAfterTheirConversationWentAreStoredAnew(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	data := []byte("gone, then back")
	thread, hash := e.inline(t, "sha256:peer", "", "m1", data)
	if out, err := e.svc.DeleteThread(ctx, e.acct, thread); err != nil || out.Files != 1 || e.fileExists(hash) {
		t.Fatalf("DeleteThread = %+v, %v; file held %v", out, err, e.fileExists(hash))
	}
	e.inline(t, "sha256:peer", "", "m2", data)
	if _, err := e.st.GetBlob(ctx, e.acct, hash); err != nil || !e.fileExists(hash) {
		t.Fatalf("the bytes sent again were not stored anew (record %v, file %v)", err, e.fileExists(hash))
	}
}

// Unlimited retention keeps messages, not files nothing names: the orphan sweep takes a file no
// message names once its record is older than FileGrace, and leaves a younger one and a named one.
func TestTheOrphanSweepTakesUnnamedFilesWhateverTheWindow(t *testing.T) {
	e := deleteEnv(t)
	ctx := context.Background()
	_, named := e.inline(t, "sha256:peer", "", "m1", []byte("named"))
	old := []byte("nothing names this")
	oldHash := hashOf(old)
	if _, err := e.blobs.Put(old); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertBlob(ctx, store.Blob{AccountID: e.acct, Hash: oldHash, Size: int64(len(old)), CreatedAt: e.clock.Add(-2 * FileGrace).Unix()}); err != nil {
		t.Fatal(err)
	}
	young := []byte("nothing names this either, yet")
	youngHash := hashOf(young)
	if _, err := e.blobs.Put(young); err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertBlob(ctx, store.Blob{AccountID: e.acct, Hash: youngHash, Size: int64(len(young)), CreatedAt: e.clock.Unix()}); err != nil {
		t.Fatal(err)
	}
	n, err := e.sweeper().CollectOrphans(ctx, e.acct)
	if err != nil || n != 1 {
		t.Fatalf("CollectOrphans = %d, %v; want the one old unnamed file", n, err)
	}
	if e.fileExists(oldHash) {
		t.Fatal("the old unnamed file is still held")
	}
	if !e.fileExists(youngHash) || !e.fileExists(named) {
		t.Fatal("the sweep took a young file or a named one")
	}
}

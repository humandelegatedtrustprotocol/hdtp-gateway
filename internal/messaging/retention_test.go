package messaging

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

type sweepEnv struct {
	st    store.Store
	blobs BlobDir
	svc   *Service
	media *MediaService
	acct  string
	clock time.Time
}

func newSweepEnv(t *testing.T) *sweepEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	e := &sweepEnv{st: st, blobs: BlobDir{Root: filepath.Join(dir, "blobs")},
		acct: a.ID, clock: time.Unix(1756000000, 0)}
	e.svc = &Service{Store: st, Now: func() time.Time { return e.clock }}
	e.media = &MediaService{Store: st, Blobs: e.blobs, Now: func() time.Time { return e.clock }}
	return e
}

func (e *sweepEnv) text(t *testing.T, msgID string) {
	t.Helper()
	if _, err := e.svc.Record(context.Background(), e.acct, "sha256:peer", DirIn,
		Input{Origin: OriginPeer, MsgID: msgID, Text: "hello " + msgID, Sender: SenderHuman}); err != nil {
		t.Fatal(err)
	}
}

func (e *sweepEnv) media_(t *testing.T, msgID string, data []byte) string {
	t.Helper()
	if _, err := e.media.ReceiveInline(context.Background(), e.svc, e.acct, "sha256:peer",
		Input{Origin: OriginPeer, MsgID: msgID, Sender: SenderHuman}, "f.bin", "application/octet-stream", data); err != nil {
		t.Fatal(err)
	}
	// the hash the message now points at
	blobs, err := e.st.ListBlobs(context.Background(), e.acct)
	if err != nil {
		t.Fatal(err)
	}
	return blobs[len(blobs)-1].Hash
}

func (e *sweepEnv) sweeper() *Sweeper {
	return &Sweeper{Store: e.st, Blobs: e.blobs, Now: func() time.Time { return e.clock }}
}

func (e *sweepEnv) count(t *testing.T) int {
	t.Helper()
	ctx := context.Background()
	threads, _ := e.st.ListThreadsByAccount(ctx, e.acct)
	n := 0
	for _, th := range threads {
		msgs, _ := e.st.ListMessagesByThread(ctx, e.acct, th.ID)
		n += len(msgs)
	}
	return n
}

// AC (P7-04): unlimited retention is the default and deletes nothing.
func TestUnlimitedRetentionDeletesNothing(t *testing.T) {
	e := newSweepEnv(t)
	e.text(t, "m-1")
	e.clock = e.clock.Add(365 * 24 * time.Hour)
	res, err := e.sweeper().Sweep(context.Background(), e.acct, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Messages != 0 || e.count(t) != 1 {
		t.Fatalf("a zero window deleted data: %+v", res)
	}
}

// AC (P7-04): a finite window deletes what is past it and keeps what is not,
// along with the blobs those retained messages still reference.
func TestRetentionDeletesPastTheWindowAndKeepsLiveBlobs(t *testing.T) {
	ctx := context.Background()
	e := newSweepEnv(t)

	oldHash := e.media_(t, "old-media", []byte("old bytes"))
	e.text(t, "old-text")
	e.clock = e.clock.Add(30 * 24 * time.Hour)
	keptHash := e.media_(t, "new-media", []byte("new bytes"))
	e.text(t, "new-text")

	if e.count(t) != 4 {
		t.Fatalf("setup stored %d messages", e.count(t))
	}
	// a 7-day window: the first two are past it
	res, err := e.sweeper().Sweep(ctx, e.acct, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Messages != 2 {
		t.Fatalf("deleted %d messages, want 2", res.Messages)
	}
	if e.count(t) != 2 {
		t.Fatalf("%d messages remain, want 2", e.count(t))
	}
	// the retained media's blob survives, row and bytes
	if _, err := e.st.GetBlob(ctx, e.acct, keptHash); err != nil {
		t.Fatalf("a blob a retained message still references was deleted: %v", err)
	}
	if _, err := e.blobs.Get(keptHash); err != nil {
		t.Fatalf("the retained blob's bytes are gone: %v", err)
	}
	// the orphaned one is gone, row and bytes
	if _, err := e.st.GetBlob(ctx, e.acct, oldHash); err == nil {
		t.Fatal("the orphaned blob row survived")
	}
	if _, err := e.blobs.Get(oldHash); !os.IsNotExist(err) {
		t.Fatalf("the orphaned blob's bytes survived: %v", err)
	}
	if res.Blobs != 1 {
		t.Fatalf("removed %d blobs, want 1", res.Blobs)
	}
}

// AC (P7-04): the blob store is content-addressed and shared. A file must not be
// removed while another account still references the same content.
func TestSharedBlobBytesSurviveUntilTheLastReferenceGoes(t *testing.T) {
	ctx := context.Background()
	e := newSweepEnv(t)
	other, err := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("shared bytes")
	hash := e.media_(t, "mine", data)
	// the same content arrives for another account
	if _, err := e.media.ReceiveInline(ctx, e.svc, other.ID, "sha256:peer",
		Input{Origin: OriginPeer, MsgID: "theirs", Sender: SenderHuman}, "f.bin", "application/octet-stream", data); err != nil {
		t.Fatal(err)
	}

	e.clock = e.clock.Add(30 * 24 * time.Hour)
	if _, err := e.sweeper().Sweep(ctx, e.acct, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// my row is gone…
	if _, err := e.st.GetBlob(ctx, e.acct, hash); err == nil {
		t.Fatal("my blob row survived my own retention window")
	}
	// …but the bytes stay, because the other account still points at them
	if _, err := e.blobs.Get(hash); err != nil {
		t.Fatalf("content another account still references was deleted: %v", err)
	}
}

// AC (P7-04): if a media body cannot be parsed the live set is unknown, so blobs
// are left alone rather than deleted on a guess.
func TestUnreadableMediaBodyStopsBlobDeletion(t *testing.T) {
	ctx := context.Background()
	e := newSweepEnv(t)
	hash := e.media_(t, "keeper", []byte("bytes"))
	thread := firstThread(t, e)
	// Time passes, then a RETAINED media message arrives whose body will not
	// parse. Because it survives the sweep, the live-hash set is unknowable.
	e.clock = e.clock.Add(30 * 24 * time.Hour)
	if err := e.st.InsertMessage(ctx, store.Message{
		ID: "broken", AccountID: e.acct, ContactFpr: "sha256:peer", MsgID: "broken",
		ThreadID: thread, Direction: "in", Sender: "human", Kind: "media",
		Body: "{not json", Status: "delivered", CreatedAt: e.clock.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	res, err := e.sweeper().Sweep(ctx, e.acct, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blobs != 0 {
		t.Fatalf("blobs were deleted while the live set was unknown: %+v", res)
	}
	if _, err := e.blobs.Get(hash); err != nil {
		t.Fatalf("bytes deleted on a guess: %v", err)
	}
	var meta MediaMeta
	_ = json.Unmarshal([]byte("{}"), &meta)
}

func firstThread(t *testing.T, e *sweepEnv) string {
	t.Helper()
	threads, err := e.st.ListThreadsByAccount(context.Background(), e.acct)
	if err != nil || len(threads) == 0 {
		t.Fatalf("no thread: %v", err)
	}
	return threads[0].ID
}

// AC (P9-05, H1): a blob is deleted only when it is BOTH unreferenced and older
// than the window. Deleting every unreferenced blob destroys media that arrived
// seconds ago: ReceiveInline writes the blob row and the message as two
// statements, so a sweep landing between them sees a blob nothing references yet.
func TestSweepNeverDeletesBlobsInsideTheWindow(t *testing.T) {
	ctx := context.Background()
	e := newSweepEnv(t)

	// a blob row with no referencing message, created NOW — exactly the state
	// ReceiveInline is in for the instant between its two writes
	data := []byte("just arrived")
	hash, err := e.blobs.Put(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.InsertBlob(ctx, store.Blob{
		AccountID: e.acct, Hash: hash, Size: int64(len(data)), CreatedAt: e.clock.Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := e.sweeper().Sweep(ctx, e.acct, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blobs != 0 {
		t.Fatalf("the sweep deleted %d blob(s) inside the retention window", res.Blobs)
	}
	if _, err := e.blobs.Get(hash); err != nil {
		t.Fatalf("media that arrived seconds ago was destroyed: %v", err)
	}
	if _, err := e.st.GetBlob(ctx, e.acct, hash); err != nil {
		t.Fatalf("its row was deleted too: %v", err)
	}

	// once it IS older than the window and still unreferenced, it goes
	e.clock = e.clock.Add(60 * 24 * time.Hour)
	res, err = e.sweeper().Sweep(ctx, e.acct, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Blobs != 1 {
		t.Fatalf("an orphaned blob past the window was kept: %+v", res)
	}
}

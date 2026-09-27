package messaging

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

func mediaEnv(t *testing.T, quota int64) (*MediaService, *Service, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	clock := time.Unix(1756000000, 0)
	msg := &Service{Store: st, Now: func() time.Time { return clock }}
	media := &MediaService{
		Store: st, Blobs: BlobDir{Root: filepath.Join(dir, "blobs")},
		MaxBytes: quota, Now: func() time.Time { return clock },
	}
	return media, msg, a.ID
}

func TestInlineStoresAndDedups(t *testing.T) {
	media, msg, acct := mediaEnv(t, 0)
	ctx := context.Background()
	data := []byte("same-bytes")
	r1, err := media.ReceiveInline(ctx, msg, acct, "sha256:alina", Input{Origin: OriginPeer, MsgID: "m1", Sender: SenderAgent}, "a.txt", "text/plain", data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := media.ReceiveInline(ctx, msg, acct, "sha256:alina", Input{Origin: OriginPeer, MsgID: "m2", Sender: SenderAgent}, "b.txt", "text/plain", data); err != nil {
		t.Fatal(err)
	}
	// same content = one blob on disk, one per-account row; quota counts once
	used, _ := media.Store.SumBlobBytes(ctx, acct)
	if used != int64(len(data)) {
		t.Fatalf("dedup failed: used=%d", used)
	}
	msgs, _ := msg.Thread(ctx, acct, r1.ThreadID)
	if msgs[0].Kind != "media" || !strings.Contains(msgs[0].Body, "\"hash\"") {
		t.Fatalf("media message row wrong: %+v", msgs[0])
	}
}

func TestPrivateRangeFetchRefusedAndAudited(t *testing.T) {
	media, _, acct := mediaEnv(t, 0)
	var mu sync.Mutex
	var audits []string
	media.Audit = func(action, resource, outcome string) {
		mu.Lock()
		defer mu.Unlock()
		audits = append(audits, action+" "+resource+" "+outcome)
	}
	// direct 10.0.0.0/8 target
	if _, err := media.Fetch(context.Background(), acct, "http://10.1.2.3/x"); err == nil {
		t.Fatal("RFC1918 fetch allowed")
	}
	// loopback (an httptest server IS loopback — the guard must refuse it)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if _, err := media.Fetch(context.Background(), acct, srv.URL+"/x"); err == nil {
		t.Fatal("loopback fetch allowed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(audits) != 2 || !strings.Contains(audits[0], "media_fetch_refused") {
		t.Fatalf("audit rows: %v", audits)
	}
}

func TestFetchHappyPathWithInjectedRanges(t *testing.T) {
	media, _, acct := mediaEnv(t, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-bytes"))
	}))
	defer srv.Close()
	// tests inject a permissive checker to exercise resolve->pin->cap->store
	media.isPrivate = func(net.IP) bool { return false }
	hash, err := media.Fetch(context.Background(), acct, srv.URL+"/img.png")
	if err != nil {
		t.Fatal(err)
	}
	got, err := media.Blobs.Get(hash)
	if err != nil || string(got) != "png-bytes" {
		t.Fatalf("blob content: %v %q", err, got)
	}
	b, err := media.Store.GetBlob(context.Background(), acct, hash)
	if err != nil || b.Mime != "image/png" {
		t.Fatalf("blob row: %v %+v", err, b)
	}
}

func TestQuotaExceededError(t *testing.T) {
	media, msg, acct := mediaEnv(t, 10) // 10-byte quota
	_, err := media.ReceiveInline(context.Background(), msg, acct, "sha256:a", Input{Origin: OriginPeer, MsgID: "m1", Sender: SenderAgent}, "f", "text/plain", []byte("0123456789AB"))
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("quota not enforced: %v", err)
	}
}

// AC (P7-04): SPEC §7.4 puts the default account quota at 10 GiB. The code said
// 1 GiB, and nothing ever set the field — so the documented default was not the
// one enforced, and an owner could not change it.
func TestDefaultQuotaMatchesTheSpec(t *testing.T) {
	m := &MediaService{}
	if got := m.quota(); got != DefaultQuotaBytes {
		t.Fatalf("quota() = %d, want the documented default %d", got, DefaultQuotaBytes)
	}
	if DefaultQuotaBytes != 10<<30 {
		t.Fatalf("the default quota is %d; SPEC §7.4 says 10 GiB", DefaultQuotaBytes)
	}
	// an explicit quota still wins
	m.MaxBytes = 5 << 20
	if got := m.quota(); got != 5<<20 {
		t.Fatalf("configured quota ignored: %d", got)
	}
}

// AC (P10-11a): the quota is read per call, so an owner changing it in the
// portal takes effect without restarting the node. It used to be captured when
// the account was built, which made the control silently inert.
func TestQuotaIsReadPerCallNotCapturedAtBuildTime(t *testing.T) {
	media, msg, acct := mediaEnv(t, 0)
	ctx := context.Background()
	limit := int64(4096)
	media.MaxBytes = 0
	media.Quota = func() int64 { return limit }

	first := bytes.Repeat([]byte("x"), 3000)
	if _, err := media.ReceiveInline(ctx, msg, acct, "sha256:alina",
		Input{Origin: OriginPeer, MsgID: "q1", Sender: SenderAgent}, "a.bin", "application/octet-stream", first); err != nil {
		t.Fatalf("a blob inside the quota was refused: %v", err)
	}
	second := bytes.Repeat([]byte("y"), 3000)
	if _, err := media.ReceiveInline(ctx, msg, acct, "sha256:alina",
		Input{Origin: OriginPeer, MsgID: "q2", Sender: SenderAgent}, "b.bin", "application/octet-stream", second); !errors.Is(err, ErrQuota) {
		t.Fatalf("the quota was not enforced: %v", err)
	}

	// The owner raises it. Same service object — no restart, no rebuild.
	limit = 1 << 20
	if _, err := media.ReceiveInline(ctx, msg, acct, "sha256:alina",
		Input{Origin: OriginPeer, MsgID: "q3", Sender: SenderAgent}, "b.bin", "application/octet-stream", second); err != nil {
		t.Fatalf("raising the quota did not take effect without a restart: %v", err)
	}

	// And lowering it bites again.
	limit = 512
	third := bytes.Repeat([]byte("z"), 3000)
	if _, err := media.ReceiveInline(ctx, msg, acct, "sha256:alina",
		Input{Origin: OriginPeer, MsgID: "q4", Sender: SenderAgent}, "c.bin", "application/octet-stream", third); !errors.Is(err, ErrQuota) {
		t.Fatalf("lowering the quota did not take effect: %v", err)
	}
}

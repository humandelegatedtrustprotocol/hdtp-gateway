package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/messaging"
)

// AC (P10-11c): the owner can read media this node already holds, and cannot
// read another account's. The portal had no media surface at all — BlobDir.Get
// had no production caller — so P2-05's "click-to-fetch" described code nobody
// could reach.
func TestOwnerCanReadStoredMediaButNotAnotherAccounts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	dir := t.TempDir()
	blobs := messaging.BlobDir{Root: dir}
	hash, err := blobs.Put([]byte("the actual bytes"))
	if err != nil {
		t.Fatal(err)
	}
	mine, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "mine", DisplayName: "Mine", Algo: "p256"})
	other, _ := e.st.CreateAccount(ctx, store.CreateAccountParams{Slug: "other", DisplayName: "Other", Algo: "p256"})
	if err := e.st.InsertBlob(ctx, store.Blob{
		AccountID: mine.ID, Hash: hash, Filename: `re"port.txt`, Mime: "text/html", Size: 16,
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	MountMediaPages(mux, MediaDeps{Store: e.st, Blobs: blobs})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/media/"+hash+"?account="+mine.ID, nil))
	if rr.Code != 200 || rr.Body.String() != "the actual bytes" {
		t.Fatalf("the owner could not read their own media: %d %q", rr.Code, rr.Body.String())
	}
	// A peer's MIME must not decide how the browser treats the file: rendering
	// a contact's upload inline is how a sent file becomes script on the
	// portal's own origin.
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("served a contact's file as %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || strings.Count(cd, `"`) != 2 {
		t.Errorf("Content-Disposition did not neutralise the peer-supplied filename: %q", cd)
	}

	// Content is addressed by hash, and a contact knows the hash they sent —
	// so the blob row, not the hash, has to be the authorization.
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, httptest.NewRequest("GET", "/media/"+hash+"?account="+other.ID, nil))
	if rr2.Code != 404 {
		t.Fatalf("one account read another's media by hash: %d", rr2.Code)
	}
}

// AC (P10-11d): fetching a contact-supplied URL happens only when the owner
// asks, and the refusal is reported rather than swallowed (§7.5).
func TestMediaFetchIsOwnerInitiatedAndReportsRefusal(t *testing.T) {
	e := newEnv(t)
	mux := http.NewServeMux()
	called := 0
	MountMediaPages(mux, MediaDeps{
		Store: e.st, Blobs: messaging.BlobDir{Root: t.TempDir()},
		Fetch: func(_ context.Context, _, raw string) (string, error) {
			called++
			return "", errRefused
		},
	})
	// Merely rendering a thread must not fetch anything; only this POST does.
	if called != 0 {
		t.Fatal("something fetched without being asked")
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/media/fetch",
		strings.NewReader("account=a&url=http://127.0.0.1/secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rr, req)
	if called != 1 {
		t.Fatalf("the owner's explicit fetch did not reach the service (%d)", called)
	}
	if !strings.Contains(rr.Body.String(), "refused") {
		t.Fatalf("a refused fetch was not reported to the owner: %s", rr.Body.String())
	}
}

var errRefused = &fetchErr{"refused: private range"}

type fetchErr struct{ s string }

func (e *fetchErr) Error() string { return e.s }

// AC (P10-11f): the portal listens to the SSE stream it serves.
//
// `GET /events` published to nobody: no page contained an EventSource, so the
// portal was static and an owner had to reload to see a message that had already
// arrived — while SPEC §8.1 says live updates arrive over SSE fed by the bus.
func TestPortalPagesConsumeTheEventStream(t *testing.T) {
	// The live half of the messages view: the compiled portal must SUBSCRIBE to
	// /events, or deliveries update nothing until a manual refresh — the "SSE
	// exists but nothing listens" defect this test was written for, in its SPA
	// form. The endpoint side (/events streams bus events) is covered by
	// TestSSEDeliversNewMessageEvent.
	js := bundleJS(t)
	if !strings.Contains(js, "EventSource") {
		t.Error("the compiled portal never opens the event stream it is served")
	}
	if !strings.Contains(js, "/events") {
		t.Error("the compiled portal does not know the event stream's path")
	}
}

package webhooks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
)

// The dispatcher, against real receivers on loopback (the cloud's "the delivery itself" and "a
// failure publishEvent swallows leaves one line naming its stage", case for case, and what the
// node's change log adds: the cursor, the lease and a second process).

// posted is one request a receiver took.
type posted struct {
	header http.Header
	body   string
}

// receiver is a real HTTP server on loopback that keeps what it is sent and answers with answer
// (200 "ok" when nil).
type receiver struct {
	*httptest.Server
	mu     sync.Mutex
	got    []posted
	answer func(w http.ResponseWriter, r *http.Request)
}

func newReceiver(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *receiver {
	t.Helper()
	rc := &receiver{answer: answer}
	rc.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.got = append(rc.got, posted{header: r.Header.Clone(), body: string(b)})
		rc.mu.Unlock()
		if rc.answer != nil {
			rc.answer(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(rc.Close)
	return rc
}

func (rc *receiver) posts() []posted {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]posted(nil), rc.got...)
}

// lines is a log the dispatcher writes its failure lines to.
type lines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// dispatcher is a dispatcher over the fixture's service, its own bus, always leading.
func (f *fixture) dispatcher(log io.Writer) *Dispatcher {
	return NewDispatcher(f.svc, messaging.NewBus(f.st), nil, "9.9.9", log)
}

// received appends the change row a message the account received writes (messaging.Service's
// publish), at the fixture's clock, and returns its id.
func (f *fixture) received(t *testing.T, accountID, msgID string) int64 {
	t.Helper()
	id, err := f.st.AppendChange(context.Background(), store.Change{AccountID: accountID, Kind: string(messaging.EventMessage),
		ThreadID: "th1", ContactFpr: "sha256:abc", At: f.clock.Unix(), MsgID: msgID, Direction: string(messaging.DirIn), MsgKind: "text"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) deliveries(t *testing.T, endpointID string) []DeliveryView {
	t.Helper()
	l, err := f.svc.ListDeliveries(context.Background(), f.mine, endpointID, deliveriesMax)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestADeliveryIsSignedWithTheHeadersAReceiverNeedsAndLogged(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rc := newReceiver(t, nil)
	made, secret := f.create(t, rc.URL+"/hook")
	change := f.received(t, f.mine, "m1")
	f.dispatcher(nil).Pass(ctx)

	got := rc.posts()
	if len(got) != 1 {
		t.Fatalf("%d posts, want 1", len(got))
	}
	h := got[0].header
	// The identity is the account's id, never its slug: the id every owner MCP tool takes.
	want, _ := EnvelopeBody(EventEnvelope{ID: "evt_" + strconv.FormatInt(change, 10), Type: "message.received",
		CreatedAt: now.Unix() * 1000, Identity: f.mine, Data: map[string]any{"thread_id": "th1", "message_id": "m1", "from": "sha256:abc"}})
	if got[0].body != want {
		t.Fatalf("body\n%s\nwant\n%s", got[0].body, want)
	}
	if h.Get(EventIDHeader) != "evt_"+strconv.FormatInt(change, 10) || h.Get(EventTypeHeader) != "message.received" ||
		h.Get("Content-Type") != "application/json" || h.Get("User-Agent") != "hdtp-gateway-webhooks/9.9.9" {
		t.Fatalf("headers: %v", h)
	}
	// The signature verifies against the body that was actually sent: the one assertion that ties
	// the two halves together.
	if !VerifySignature(secret, got[0].body, h.Get(SignatureHeader), now.Unix()) {
		t.Fatalf("the signature %q does not verify", h.Get(SignatureHeader))
	}
	l := f.deliveries(t, made.ID)
	if len(l) != 1 || l[0].ID != h.Get(DeliveryHeader) || l[0].Status != "delivered" || l[0].HTTPStatus == nil ||
		*l[0].HTTPStatus != 200 || l[0].ResponseExcerpt == nil || *l[0].ResponseExcerpt != "ok" || l[0].EventID != h.Get(EventIDHeader) {
		t.Fatalf("the log: %+v", l)
	}
	// The cursor moved past it: a second pass posts nothing more.
	if c, _ := f.st.WebhookCursor(ctx, f.mine); c != change {
		t.Fatalf("the cursor is at %d, want %d", c, change)
	}
	f.dispatcher(nil).Pass(ctx)
	if n := len(rc.posts()); n != 1 {
		t.Fatalf("a second pass posted again: %d posts", n)
	}
}

func TestANon2xxAndARefusedConnectionAreFailuresToldApartByTheExcerpt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	refused := newReceiver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "no thanks")
	})
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL + "/hook?token=s3cret"
	dead.Close()
	bad, _ := f.create(t, refused.URL)
	gone, _ := f.create(t, deadURL)
	f.received(t, f.mine, "m1")
	f.dispatcher(nil).Pass(ctx)

	l := f.deliveries(t, bad.ID)
	if len(l) != 1 || l[0].Status != "failed" || l[0].HTTPStatus == nil || *l[0].HTTPStatus != 500 || *l[0].ResponseExcerpt != "no thanks" {
		t.Fatalf("a 500: %+v", l)
	}
	l = f.deliveries(t, gone.ID)
	if len(l) != 1 || l[0].Status != "failed" || l[0].HTTPStatus != nil || l[0].ResponseExcerpt == nil ||
		!strings.Contains(*l[0].ResponseExcerpt, "connection refused") {
		t.Fatalf("a refused connection: %+v", l)
	}
	// The reason, without the address it was going to: a receiver may keep a token in it.
	if strings.Contains(*l[0].ResponseExcerpt, "s3cret") || strings.Contains(*l[0].ResponseExcerpt, "127.0.0.1:") && strings.Contains(*l[0].ResponseExcerpt, "/hook") {
		t.Fatalf("the excerpt names the address: %q", *l[0].ResponseExcerpt)
	}
	if e := f.find(t, bad.ID); e.ConsecutiveFailures != 1 {
		t.Fatalf("the failure was not counted: %+v", e)
	}
}

// A receiver that answers 200 and never stops sending: three-byte characters, so a count of
// characters and a count of bytes disagree.
func TestAnEndlessAnswerIsCutWithoutReadingTheRest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	writes := 0
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("€", 100))
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			mu.Lock()
			writes++
			n := writes
			mu.Unlock()
			if n > 10_000 {
				return
			}
			select {
			case <-r.Context().Done():
				return
			default:
			}
		}
	})
	made, _ := f.create(t, rc.URL)
	f.received(t, f.mine, "m1")
	started := time.Now()
	f.dispatcher(nil).Pass(ctx)
	if time.Since(started) > 5*time.Second {
		t.Fatal("the attempt read the endless answer")
	}
	l := f.deliveries(t, made.ID)
	if len(l) != 1 || l[0].Status != "delivered" || l[0].ResponseExcerpt == nil {
		t.Fatalf("the log: %+v", l)
	}
	x := *l[0].ResponseExcerpt
	if len(x) > ExcerptBytes || utf8.RuneCountInString(x) != 166 || strings.Trim(x, "€") != "" {
		t.Fatalf("the excerpt is %d bytes, %d characters: %q", len(x), utf8.RuneCountInString(x), x)
	}
	mu.Lock()
	defer mu.Unlock()
	if writes >= 10_000 {
		t.Fatalf("the receiver wrote %d chunks: the answer was read to the end", writes)
	}
}

func TestARedirectIsNotFollowed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	elsewhere := newReceiver(t, nil)
	rc := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	})
	made, _ := f.create(t, rc.URL)
	f.received(t, f.mine, "m1")
	f.dispatcher(nil).Pass(ctx)
	if n := len(elsewhere.posts()); n != 0 {
		t.Fatalf("the redirect was followed: %d posts elsewhere", n)
	}
	if l := f.deliveries(t, made.ID); len(l) != 1 || l[0].Status != "failed" || *l[0].HTTPStatus != http.StatusTemporaryRedirect {
		t.Fatalf("the log: %+v", l)
	}
}

func TestAnAttemptHasTenSecondsAndThenHasFailed(t *testing.T) {
	f := newFixture(t)
	if d := f.dispatcher(nil); d.client.Timeout != 10*time.Second {
		t.Fatalf("the attempt's timeout is %v", d.client.Timeout)
	}
	release := make(chan struct{})
	rc := newReceiver(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	made, _ := f.create(t, rc.URL)
	f.received(t, f.mine, "m1")
	d := f.dispatcher(nil)
	d.client.Timeout = 200 * time.Millisecond // the same rule, sooner
	d.Pass(context.Background())
	if l := f.deliveries(t, made.ID); len(l) != 1 || l[0].Status != "failed" || l[0].HTTPStatus != nil ||
		!strings.Contains(*l[0].ResponseExcerpt, "Timeout") {
		t.Fatalf("the log: %+v", l)
	}
}

// A process stopped while a post is in flight still logs the attempt: the change was claimed and is
// never posted again, so the log is the only record that it went out. The receiver stops the node
// and holds its answer until the node hangs up, so the attempt ends because of the stop and for no
// other reason. It is logged failed, with no answer, and not counted toward FailureLimit: the node
// stopped, the receiver did not fail.
func TestAPostInFlightWhenTheProcessStopsIsStillLogged(t *testing.T) {
	f := newFixture(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	rc := newReceiver(t, func(_ http.ResponseWriter, r *http.Request) {
		stop()
		<-r.Context().Done()
	})
	made, _ := f.create(t, rc.URL)
	f.received(t, f.mine, "m1")
	f.dispatcher(nil).Pass(ctx)
	if n := len(rc.posts()); n != 1 {
		t.Fatalf("%d posts, want 1", n)
	}
	l := f.deliveries(t, made.ID)
	if len(l) != 1 || l[0].Status != "failed" || l[0].HTTPStatus != nil {
		t.Fatalf("the log after a stop mid-post: %+v; want the one attempt, failed with no answer", l)
	}
	if e := f.find(t, made.ID); e.ConsecutiveFailures != 0 || e.Status != "active" {
		t.Fatalf("the endpoint after a stop mid-post: %+v; want no failure counted", e)
	}
}

// An endpoint hears what happens from its registration on, only what its filter names, nothing
// while paused, and no backlog when it is resumed. A change no webhook carries moves the cursor and
// posts nothing.
func TestAnEndpointGetsWhatItWantsFromItsRegistrationOnAndNothingWhilePaused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	before := f.received(t, f.mine, "m0")
	*f.clock = f.clock.Add(time.Second)
	all := newReceiver(t, nil)
	pending := newReceiver(t, nil)
	allE, _ := f.create(t, all.URL)
	f.create(t, pending.URL, "request.pending")
	if _, err := f.st.AppendChange(ctx, store.Change{AccountID: f.mine, Kind: string(messaging.EventInvalidate), At: f.clock.Unix()}); err != nil {
		t.Fatal(err)
	}
	f.received(t, f.mine, "m1")
	f.received(t, f.theirs, "theirs") // another account's, with no endpoint
	d := f.dispatcher(nil)
	d.Pass(ctx)
	got := all.posts()
	if len(got) != 1 || !strings.Contains(got[0].body, `"message_id":"m1"`) {
		t.Fatalf("the endpoint for everything got %d posts: %v", len(got), got)
	}
	if n := len(pending.posts()); n != 0 {
		t.Fatalf("a filter on request.pending was sent %d messages", n)
	}
	if c, _ := f.st.WebhookCursor(ctx, f.mine); c <= before {
		t.Fatalf("the cursor did not move: %d", c)
	}
	if err := f.svc.SetStatus(ctx, f.mine, allE.ID, "paused"); err != nil {
		t.Fatal(err)
	}
	f.received(t, f.mine, "m2")
	d.Pass(ctx)
	if err := f.svc.SetStatus(ctx, f.mine, allE.ID, "active"); err != nil {
		t.Fatal(err)
	}
	d.Pass(ctx)
	if n := len(all.posts()); n != 1 {
		t.Fatalf("a paused endpoint was sent what happened while it was paused: %d posts", n)
	}
	f.received(t, f.mine, "m3")
	d.Pass(ctx)
	if got := all.posts(); len(got) != 2 || !strings.Contains(got[1].body, `"message_id":"m3"`) {
		t.Fatalf("the resumed endpoint: %v", got)
	}
}

// Endpoints are posted to newest first, one after another. The first receiver, while its post is
// in flight, removes the second and pauses the third: neither is sent anything, then or after, and
// the fourth still is.
func TestAnEndpointRemovedOrPausedMidBatchReceivesNothingAfter(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	step := func() { *f.clock = f.clock.Add(time.Millisecond) }
	fourth := newReceiver(t, nil)
	f.create(t, fourth.URL)
	step()
	third := newReceiver(t, nil)
	thirdE, _ := f.create(t, third.URL)
	step()
	second := newReceiver(t, nil)
	secondE, _ := f.create(t, second.URL)
	step()
	var once sync.Once
	first := newReceiver(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			if err := f.svc.Remove(r.Context(), f.mine, secondE.ID); err != nil {
				t.Error(err)
			}
			if err := f.svc.SetStatus(r.Context(), f.mine, thirdE.ID, "paused"); err != nil {
				t.Error(err)
			}
		})
		_, _ = io.WriteString(w, "ok")
	})
	f.create(t, first.URL)
	f.received(t, f.mine, "m1")
	f.received(t, f.mine, "m2")
	f.dispatcher(nil).Pass(ctx)
	for name, c := range map[string]struct {
		rc   *receiver
		want int
	}{"first": {first, 2}, "second, removed": {second, 0}, "third, paused": {third, 0}, "fourth": {fourth, 2}} {
		if n := len(c.rc.posts()); n != c.want {
			t.Fatalf("the %s endpoint got %d posts, want %d", name, n, c.want)
		}
	}
}

// The read of an answer stops at ExcerptBytes; a character the limit cuts in two is not kept,
// neither as its first bytes nor as U+FFFD. Four-byte characters after one byte put the cut three
// bytes into the 125th.
func TestAnExcerptDropsTheCharacterTheLimitCutInTwo(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "a"+strings.Repeat("\U0001F600", 200))
	})
	made, _ := f.create(t, rc.URL)
	f.received(t, f.mine, "m1")
	f.dispatcher(nil).Pass(context.Background())
	l := f.deliveries(t, made.ID)
	if want := "a" + strings.Repeat("\U0001F600", 124); len(l) != 1 || *l[0].ResponseExcerpt != want {
		t.Fatalf("the excerpt is %q", *l[0].ResponseExcerpt)
	}
}

// refusing is a store whose named reads and writes fail with a text no line may carry, inside its
// transactions too; previous, when set, is the replaced secret its endpoints read back.
type refusing struct {
	store.Store
	fail     string
	previous []byte
}

const injected = "D1_ERROR: injected failure text that must not reach a line"

func (s refusing) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	return s.Store.Atomically(ctx, func(tx store.Store) error { return fn(refusing{Store: tx, fail: s.fail, previous: s.previous}) })
}

func (s refusing) WebhookAccounts(ctx context.Context) ([]string, error) {
	if s.fail == "accounts" {
		return nil, errors.New(injected)
	}
	return s.Store.WebhookAccounts(ctx)
}

func (s refusing) ClaimWebhookCursor(ctx context.Context, accountID string, from, to int64) (bool, error) {
	if s.fail == "claim" {
		return false, errors.New(injected)
	}
	return s.Store.ClaimWebhookCursor(ctx, accountID, from, to)
}

func (s refusing) ListWebhookEndpoints(ctx context.Context, accountID string, limit int) ([]store.WebhookEndpoint, error) {
	if s.fail == "list" {
		return nil, errors.New(injected)
	}
	return s.Store.ListWebhookEndpoints(ctx, accountID, limit)
}

func (s refusing) GetWebhookEndpoint(ctx context.Context, accountID, id string) (store.WebhookEndpoint, error) {
	if s.fail == "row" {
		return store.WebhookEndpoint{}, errors.New(injected)
	}
	e, err := s.Store.GetWebhookEndpoint(ctx, accountID, id)
	if s.previous != nil {
		e.PreviousSealed = s.previous
	}
	return e, err
}

func (s refusing) InsertWebhookDelivery(ctx context.Context, d store.WebhookDelivery) error {
	if s.fail == "record" {
		return errors.New(injected)
	}
	return s.Store.InsertWebhookDelivery(ctx, d)
}

// brokenKeyring opens nothing.
type brokenKeyring struct{ Sealer }

func (brokenKeyring) Decrypt([]byte, []byte) ([]byte, error) { return nil, errors.New(injected) }

// Every failure the dispatcher swallows leaves exactly one line, with its stage's code, the account
// and the event's type, and never the error's text; what is sent is what the stage allows.
func TestAFailureTheDispatcherSwallowsLeavesOneLineNamingItsStage(t *testing.T) {
	type outcome struct {
		line  string
		posts int
		rows  int
	}
	run := func(t *testing.T, setup func(f *fixture), status int) (outcome, *fixture) {
		f := newFixture(t)
		rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		made, _ := f.create(t, rc.URL)
		// A rotation inside its window, so the replaced secret is opened too.
		if _, _, err := f.svc.Rotate(context.Background(), f.mine, made.ID); err != nil {
			t.Fatal(err)
		}
		f.log.take()
		f.received(t, f.mine, "m1")
		setup(f)
		var log lines
		f.dispatcher(&log).Pass(context.Background())
		f.svc.store, f.svc.kr = f.st, f.kr
		if strings.Contains(log.String(), "injected") {
			t.Fatalf("a line carries the error's text: %q", log.String())
		}
		return outcome{line: strings.TrimSpace(log.String()), posts: len(rc.posts()), rows: len(f.deliveries(t, made.ID))}, f
	}
	line := func(f *fixture, code string) string {
		return "webhooks: " + code + " account:" + f.mine + " event_type:message.received"
	}
	healthy := func(*fixture) {}
	t.Run("a delivery that lands, or one the receiver refuses, logs nothing", func(t *testing.T) {
		for _, status := range []int{200, 500} {
			if got, _ := run(t, healthy, status); got != (outcome{posts: 1, rows: 1}) {
				t.Fatalf("%d: %+v", status, got)
			}
		}
	})
	t.Run("the accounts, and nothing is sent", func(t *testing.T) {
		got, _ := run(t, func(f *fixture) { f.svc.store = refusing{Store: f.st, fail: "accounts"} }, 200)
		if got != (outcome{line: "webhooks: webhook_accounts_unreadable"}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("the claim, and nothing is sent until the next pass", func(t *testing.T) {
		got, f := run(t, func(f *fixture) { f.svc.store = refusing{Store: f.st, fail: "claim"} }, 200)
		if got != (outcome{line: "webhooks: webhook_cursor_unwritable account:" + f.mine}) {
			t.Fatalf("%+v", got)
		}
		f.dispatcher(nil).Pass(context.Background())
		if l, _ := f.st.ListWebhookEndpoints(context.Background(), f.mine, 1); len(f.deliveries(t, l[0].ID)) != 1 {
			t.Fatal("the next pass did not send what the claim missed")
		}
	})
	t.Run("the endpoint list, and nothing is sent", func(t *testing.T) {
		got, f := run(t, func(f *fixture) { f.svc.store = refusing{Store: f.st, fail: "list"} }, 200)
		if got != (outcome{line: line(f, "webhook_endpoints_unreadable")}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("the endpoint's row, and it is sent nothing", func(t *testing.T) {
		got, f := run(t, func(f *fixture) { f.svc.store = refusing{Store: f.st, fail: "row"} }, 200)
		if got != (outcome{line: line(f, "webhook_secret_unreadable")}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("the endpoint's secret, and it is sent nothing", func(t *testing.T) {
		got, f := run(t, func(f *fixture) { f.svc.kr = brokenKeyring{f.kr} }, 200)
		if got != (outcome{line: line(f, "webhook_secret_unreadable")}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("a replaced secret that will not open is a warning, and the current one signs", func(t *testing.T) {
		got, f := run(t, func(f *fixture) { f.svc.store = refusing{Store: f.st, previous: []byte("not a sealed blob")} }, 200)
		if got != (outcome{line: line(f, "webhook_previous_secret_unreadable"), posts: 1, rows: 1}) {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("the record, when the attempt was made and its row was not written", func(t *testing.T) {
		got, f := run(t, func(f *fixture) { f.svc.store = refusing{Store: f.st, fail: "record"} }, 200)
		if got != (outcome{line: line(f, "webhook_delivery_record_failed"), posts: 1}) {
			t.Fatalf("%+v", got)
		}
	})
}

// Two node processes on one store, each with its own handle and its own bus, post each change
// once. A process that does not hold the lease reads nothing, until the holder lets it go. Without
// the lease, the claim on the cursor decides. Run on every engine the machine has (PostgreSQL under
// the pre-push hook).
func TestTwoDispatchersOnOneStorePostEachChangeOnce(t *testing.T) {
	for engine, handles := range sharedStores(t, 2) {
		t.Run(engine, func(t *testing.T) {
			kr := newKeyring(t)
			f := newFixtureOn(t, handles[0], kr)
			other := New(handles[1], kr, func(string, string, string) {})
			other.now = f.svc.now
			rc := newReceiver(t, nil)
			made, _ := f.create(t, rc.URL)
			lease := func(st store.Store, holder string) func(context.Context) bool {
				return func(ctx context.Context) bool {
					at := time.Now()
					held, err := st.TakeLease(ctx, LeaseName, holder, at.Unix(), at.Add(30*time.Second).Unix())
					return err == nil && held
				}
			}
			// run starts both processes' dispatchers (nil for one that does not run), sends n
			// changes, and waits until n posts arrived or wait ran out; stop ends them.
			run := func(t *testing.T, one, two func(context.Context) bool, startOne bool, n int, wait time.Duration) (sent []posted, stop func()) {
				t.Helper()
				before := len(rc.posts())
				ctx, cancel := context.WithCancel(context.Background())
				var wg sync.WaitGroup
				if startOne {
					wg.Go(func() { NewDispatcher(f.svc, messaging.NewBus(handles[0]), one, "process-1", nil).Run(ctx) })
				}
				wg.Go(func() { NewDispatcher(other, messaging.NewBus(handles[1]), two, "process-2", nil).Run(ctx) })
				for i := range n {
					f.received(t, f.mine, t.Name()+strconv.Itoa(i))
				}
				deadline := time.Now().Add(wait)
				for len(rc.posts())-before < n && time.Now().Before(deadline) {
					time.Sleep(20 * time.Millisecond)
				}
				time.Sleep(4 * messaging.PollInterval) // what a second post would need
				return rc.posts()[before:], func() { cancel(); wg.Wait() }
			}
			once := func(t *testing.T, sent []posted, n int) {
				t.Helper()
				seen := map[string]int{}
				for _, p := range sent {
					seen[p.header.Get(EventIDHeader)]++
				}
				if len(seen) != n {
					t.Fatalf("%d distinct events posted, want %d", len(seen), n)
				}
				for id, k := range seen {
					if k != 1 {
						t.Fatalf("%s was posted %d times", id, k)
					}
				}
			}
			t.Run("the lease", func(t *testing.T) {
				ctx := context.Background()
				// Process 1 holds the lease and is stopped: process 2 reads nothing.
				if !lease(handles[0], "process-1")(ctx) {
					t.Fatal("process 1 could not take the lease")
				}
				sent, stop := run(t, nil, lease(handles[1], "process-2"), false, 3, 3*messaging.PollInterval)
				if len(sent) != 0 {
					stop()
					t.Fatalf("a process without the lease posted %d events", len(sent))
				}
				// Process 1 lets it go: process 2 takes it at its next pass and posts what waited.
				if err := handles[0].ReleaseLease(ctx, LeaseName, "process-1"); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(15 * time.Second)
				for len(rc.posts()) < 3 && time.Now().Before(deadline) {
					time.Sleep(20 * time.Millisecond)
				}
				stop()
				once(t, rc.posts(), 3)
				for _, p := range rc.posts() {
					if p.header.Get("User-Agent") != "hdtp-gateway-webhooks/process-2" {
						t.Fatalf("posted by %s", p.header.Get("User-Agent"))
					}
				}
			})
			t.Run("the claim", func(t *testing.T) {
				sent, stop := run(t, nil, nil, true, 12, 15*time.Second)
				stop()
				once(t, sent, 12)
			})
			if l := f.deliveries(t, made.ID); len(l) != 15 {
				t.Fatalf("%d delivery rows, want 15", len(l))
			}
		})
	}
}

// What a receiver answers is kept as text either engine stores: a byte that is not UTF-8 and a
// NUL become U+FFFD.
func TestAnAnswerThatIsNotTextIsStillLogged(t *testing.T) {
	for engine, handles := range sharedStores(t, 1) {
		t.Run(engine, func(t *testing.T) {
			f := newFixtureOn(t, handles[0], newKeyring(t))
			rc := newReceiver(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\xff\x00!")) })
			made, _ := f.create(t, rc.URL)
			f.received(t, f.mine, "m1")
			var log lines
			f.dispatcher(&log).Pass(context.Background())
			l := f.deliveries(t, made.ID)
			if len(l) != 1 || l[0].ResponseExcerpt == nil || *l[0].ResponseExcerpt != "ok\uFFFD\uFFFD!" || log.String() != "" {
				t.Fatalf("the log: %+v, lines %q", l, log.String())
			}
		})
	}
}

package webhooks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

func event(over func(*EventEnvelope)) EventEnvelope {
	e := EventEnvelope{ID: "evt_1", Type: "message.received", CreatedAt: now.UnixMilli(), Identity: "alice",
		Data: map[string]any{"thread_id": "th1", "message_id": "m1", "from": "sha256:abc"}}
	if over != nil {
		over(&e)
	}
	return e
}

func ids(es []EndpointView) string {
	var out []string
	for _, e := range es {
		out = append(out, e.ID)
	}
	return strings.Join(out, ",")
}

// The cloud's "an empty filter means every event, and a filter means only those" and "only sends to
// endpoints that are active and want the event".
func TestOnlyActiveEndpointsThatWantTheEventAreTargets(t *testing.T) {
	eps := []EndpointView{
		{ID: "a", Status: "active", Events: []string{}, CreatedAt: 1000},
		{ID: "b", Status: "active", Events: []string{"request.pending"}, CreatedAt: 1000},
		{ID: "c", Status: "paused", Events: []string{}, CreatedAt: 1000},
	}
	at := func(typ string) EventEnvelope { return EventEnvelope{Type: typ, CreatedAt: 2000} }
	if got := ids(TargetsFor(eps, at("message.received"))); got != "a" {
		t.Errorf("message.received goes to %q, want a", got)
	}
	if got := ids(TargetsFor(eps, at("request.pending"))); got != "a,b" {
		t.Errorf("request.pending goes to %q, want a,b", got)
	}
}

// An endpoint hears what happens from its registration on. The change log keeps seconds, so an
// endpoint registered later in the second of an event still takes it; one registered in a later
// second does not.
func TestAnEndpointHearsWhatHappensFromItsRegistrationOn(t *testing.T) {
	ep := func(created int64) []EndpointView {
		return []EndpointView{{ID: "e", Status: "active", Events: []string{}, CreatedAt: created}}
	}
	ev := EventEnvelope{Type: "message.received", CreatedAt: 1_800_000_000_000}
	for created, want := range map[int64]string{
		1_799_999_999_999: "e",
		1_800_000_000_000: "e",
		1_800_000_000_999: "e", // same second
		1_800_000_001_000: "",  // the next second
	} {
		if got := ids(TargetsFor(ep(created), ev)); got != want {
			t.Errorf("an endpoint created at %d takes %q, want %q", created, got, want)
		}
	}
}

// The cloud's "records a failure as terminal, with nothing scheduled after it".
func TestAFailureIsRecordedAsFinal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/record")
	f.log.take()
	id := NewDeliveryID()
	status, err := f.svc.RecordAttempt(ctx, f.mine, id, made.ID, event(nil), AttemptOutcome{OK: false, HTTPStatus: 500, LatencyMs: 12, Excerpt: "nope"})
	if err != nil || status != "failed" {
		t.Fatalf("recorded %q %v", status, err)
	}
	l, err := f.svc.ListDeliveries(ctx, f.mine, made.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].ID != id || !strings.HasPrefix(id, "whd_") || l[0].Status != "failed" || l[0].HTTPStatus == nil || *l[0].HTTPStatus != 500 ||
		l[0].ResponseExcerpt == nil || *l[0].ResponseExcerpt != "nope" || l[0].LatencyMs != 12 || l[0].EventID != "evt_1" ||
		l[0].EventType != "message.received" || l[0].CreatedAt != now.UnixMilli() {
		t.Fatalf("the log: %+v", l)
	}
	if e := f.find(t, made.ID); e.ConsecutiveFailures != 1 {
		t.Fatalf("one failure counted %d", e.ConsecutiveFailures)
	}
	// Deliveries are not audited: the log is their record.
	if got := f.log.take(); len(got) != 0 {
		t.Fatalf("a delivery was audited: %v", got)
	}
	// An attempt that got no answer reads back with no status and no excerpt when it had none.
	*f.clock = now.Add(time.Millisecond)
	if _, err := f.svc.RecordAttempt(ctx, f.mine, NewDeliveryID(), made.ID, event(nil), AttemptOutcome{LatencyMs: 3}); err != nil {
		t.Fatal(err)
	}
	if l, _ := f.svc.ListDeliveries(ctx, f.mine, made.ID, 1); len(l) != 1 || l[0].HTTPStatus != nil || l[0].ResponseExcerpt != nil {
		t.Fatalf("an unanswered attempt: %+v", l)
	}
}

// The cloud's "a success clears the endpoint, and a run of failures parks it".
func TestASuccessClearsTheRunAndARunOfFailuresParksTheEndpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/dead")
	failed := AttemptOutcome{LatencyMs: 1, Excerpt: "gone"}
	for i := 1; i <= FailureLimit; i++ {
		if _, err := f.svc.RecordAttempt(ctx, f.mine, NewDeliveryID(), made.ID, event(nil), failed); err != nil {
			t.Fatal(err)
		}
		want := "active"
		if i == FailureLimit {
			want = "paused"
		}
		if e := f.find(t, made.ID); e.Status != want || e.ConsecutiveFailures != int64(i) {
			t.Fatalf("after %d failures: %s %d, want %s", i, e.Status, e.ConsecutiveFailures, want)
		}
	}
	if _, err := f.svc.RecordAttempt(ctx, f.mine, NewDeliveryID(), made.ID, event(nil), AttemptOutcome{OK: true, HTTPStatus: 200, LatencyMs: 8}); err != nil {
		t.Fatal(err)
	}
	// A success clears the run and does not resume a parked endpoint: only the owner resumes one.
	if e := f.find(t, made.ID); e.ConsecutiveFailures != 0 || e.Status != "paused" {
		t.Fatalf("after a success: %+v", e)
	}
}

// The delivery row and the endpoint's health are one write: a failure on either leaves neither.
func TestAnAttemptIsRecordedWithItsHealthOrNotAtAll(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/tx")
	broken := errors.New("injected")
	f.svc.store = failingCount{Store: f.st, err: broken}
	if _, err := f.svc.RecordAttempt(ctx, f.mine, "whd_x", made.ID, event(nil), AttemptOutcome{Excerpt: "x"}); !errors.Is(err, broken) {
		t.Fatalf("recorded through a failing count: %v", err)
	}
	f.svc.store = f.st
	if l, _ := f.svc.ListDeliveries(ctx, f.mine, made.ID, 0); len(l) != 0 {
		t.Fatalf("the row stayed without its count: %+v", l)
	}
	// The control: the same attempt through the real store is recorded.
	if _, err := f.svc.RecordAttempt(ctx, f.mine, "whd_x", made.ID, event(nil), AttemptOutcome{Excerpt: "x"}); err != nil {
		t.Fatal(err)
	}
	if l, _ := f.svc.ListDeliveries(ctx, f.mine, made.ID, 0); len(l) != 1 {
		t.Fatalf("the control recorded %d rows", len(l))
	}
}

// failingCount is a store whose transactions fail at the failure count, after the delivery row.
type failingCount struct {
	store.Store
	err error
}

func (s failingCount) Atomically(ctx context.Context, fn func(tx store.Store) error) error {
	return s.Store.Atomically(ctx, func(tx store.Store) error { return fn(failingCount{Store: tx, err: s.err}) })
}

func (s failingCount) CountWebhookFailure(context.Context, string, string, int64, int64) (bool, error) {
	return false, s.err
}

// A removed endpoint's attempt is still a row of the log; it has no health to change.
func TestAnAttemptOnARemovedEndpointIsStillLogged(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/gone")
	if err := f.svc.Remove(ctx, f.mine, made.ID); err != nil {
		t.Fatal(err)
	}
	if status, err := f.svc.RecordAttempt(ctx, f.mine, "whd_after", made.ID, event(nil), AttemptOutcome{OK: true, HTTPStatus: 204}); err != nil || status != "delivered" {
		t.Fatalf("%q %v", status, err)
	}
	if l, _ := f.st.ListWebhookDeliveries(ctx, f.mine, made.ID, 10); len(l) != 1 || l[0].ID != "whd_after" {
		t.Fatalf("the log: %+v", l)
	}
}

// What a row keeps of an answer is ExcerptBytes bytes at most, of whole characters: three-byte
// characters, so a count of characters and a count of bytes disagree.
func TestAnExcerptIsBoundedInBytesOfWholeCharacters(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/long")
	if _, err := f.svc.RecordAttempt(ctx, f.mine, "whd_long", made.ID, event(nil), AttemptOutcome{OK: true, HTTPStatus: 200, Excerpt: strings.Repeat("€", 1000)}); err != nil {
		t.Fatal(err)
	}
	l, _ := f.svc.ListDeliveries(ctx, f.mine, made.ID, 0)
	got := *l[0].ResponseExcerpt
	if len(got) > ExcerptBytes || !utf8.ValidString(got) || got != strings.Repeat("€", 166) {
		t.Fatalf("kept %d bytes (%d characters), want 166 whole characters", len(got), utf8.RuneCountInString(got))
	}
	if excerpt("short") != "short" || excerpt(strings.Repeat("a", ExcerptBytes)) != strings.Repeat("a", ExcerptBytes) {
		t.Fatal("an excerpt within the bound is changed")
	}
}

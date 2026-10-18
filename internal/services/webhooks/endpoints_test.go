package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
)

// Which URLs the node posts to (the cloud's "which URLs we are willing to dial", with ruling A of
// docs/release/webhooks-2026-10-18.md: what the cloud refuses as not_https, literal_address and
// private_name the node takes, because only its owner registers an endpoint and the receiver is
// often an agent beside it).

func TestAURLIsAnHTTPOrHTTPSURLWithAHostAndNoCredentials(t *testing.T) {
	for raw, want := range map[string]string{
		"https://hooks.example.test/hdtp": "",
		"  https://hooks.example.test/x ": "",
		"not a url":                       NotAURL,
		"":                                NotAURL,
		"::::":                            NotAURL,
		"hooks.example.test/hdtp":         NotAURL, // no scheme: a path, not a URL
		"ftp://hooks.example.test/":       NotAURL, // the cloud's not_https; neither host posts to ftp
		"mailto:a@example.test":           NotAURL,
		"https:///nohost":                 NotAURL,
		// Reads as hooks.example.test, dials evil.test.
		"https://hooks.example.test@evil.test/hdtp": HasCredentials,
		"http://user:pass@hooks.example.test/":      HasCredentials,
		// Bounded in bytes: MaxURLBytes is taken, one more is not.
		longURL(MaxURLBytes):     "",
		longURL(MaxURLBytes + 1): URLTooLong,
	} {
		if got := CheckEndpointURL(raw); got != want {
			t.Errorf("CheckEndpointURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// longURL is an https URL of exactly n bytes.
func longURL(n int) string {
	const head = "https://hooks.example.test/"
	return head + strings.Repeat("a", n-len(head))
}

// Ruling A: every URL the cloud's test refuses as not_https, literal_address or private_name is a
// receiver the node posts to.
func TestTheNodeTakesTheAddressesTheCloudRefuses(t *testing.T) {
	for _, raw := range []string{
		"http://hooks.example.test/hdtp",
		"https://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1/admin",
		"http://127.0.0.1:8787/hook",
		"https://10.0.0.5/internal",
		"https://192.168.1.1/",
		"https://[::1]/",
		"https://[fd00::1]/",
		"https://localhost/hook",
		"https://api.localhost/hook",
		"https://box.local/",
		"https://svc.internal/",
		"http://agent:3000/webhook", // a compose service name
	} {
		if got := CheckEndpointURL(raw); got != "" {
			t.Errorf("CheckEndpointURL(%q) = %q, want it taken (ruling A)", raw, got)
		}
	}
}

// The reasons are different mistakes, so each says its own; and the words are the cloud's.
func TestEachRefusalSaysItsOwnReasonInTheCloudsWords(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, c := range []struct {
		url    string
		events []string
		code   string
		detail string
	}{
		{"not a url", nil, NotAURL, "That is not a URL."},
		{"https://a@b.example.test/", nil, HasCredentials,
			"Take the username and password out of the URL — a URL that carries them reads as one host and dials another."},
		{"https://hooks.example.test/x", []string{"message.recieved"}, UnknownEvent,
			"message.recieved is not an event we send, so a filter on it would never fire. The ones we send are listed on this page."},
		// The node's own: the cloud bounds no URL.
		{longURL(MaxURLBytes + 1), nil, URLTooLong, "That URL is longer than 2048 bytes, the most an endpoint takes."},
	} {
		_, secret, err := f.svc.Create(ctx, f.mine, c.url, c.events)
		var r Refused
		if !errors.As(err, &r) || r.Code != c.code || secret != "" {
			t.Fatalf("%s: %v (secret %q), want the refusal %s", c.url, err, secret, c.code)
		}
		if code, detail := refusal.Of(err); code != "bad_request" || detail != c.detail {
			t.Errorf("%s: a door reads %s %q, want bad_request %q", c.url, code, detail, c.detail)
		}
	}
	if l, _ := f.svc.List(ctx, f.mine); len(l) != 0 {
		t.Fatalf("a refused registration stored %d endpoints", len(l))
	}
	if got := joined(f.log.take()); strings.Count(got, "webhook_create account:"+f.mine+" bad_request") != 4 {
		t.Fatalf("each refusal is audited once under its account:\n%s", got)
	}
}

func TestAnEndpointIsRegisteredFiltersOnEmittedEventsAndIsShownItsSecretOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, secret := f.create(t, " https://hooks.example.test:8443/hdtp?token=t0ken ", "message.received", "request.pending", "message.received")
	if !strings.HasPrefix(secret, "whsec_") || !strings.HasPrefix(made.ID, "whe_") {
		t.Fatalf("made %+v with secret %q", made, secret)
	}
	if made.URL != "https://hooks.example.test:8443/hdtp?token=t0ken" || made.Status != "active" || made.ConsecutiveFailures != 0 ||
		made.RotatingUntil != nil || made.CreatedAt != now.UnixMilli() || made.UpdatedAt != now.UnixMilli() {
		t.Fatalf("the new endpoint: %+v", made)
	}
	row := f.find(t, made.ID)
	if strings.Join(row.Events, ",") != "message.received,request.pending" {
		t.Fatalf("the filter is %v, want it as given without the repeat", row.Events)
	}
	// The listing carries no secret and no sealed blob. Asserted over the serialised form, because
	// a field added later would slip past a field-by-field check.
	l, err := f.svc.List(ctx, f.mine)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(l)
	stored, _ := f.st.GetWebhookEndpoint(ctx, f.mine, made.ID)
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "sealed") || strings.Contains(string(stored.URL), secret) {
		t.Fatalf("the listing carries the secret: %s", b)
	}
	// What the store holds is sealed, not the secret.
	if strings.Contains(string(stored.SecretSealed), secret) || len(stored.SecretSealed) == 0 {
		t.Fatal("the stored secret is not sealed")
	}
	var keys map[string]any
	_ = json.Unmarshal(mustJSON(t, l[0]), &keys)
	want := []string{"consecutive_failures", "created_at", "events", "id", "rotating_until", "status", "updated_at", "url"}
	if len(keys) != len(want) {
		t.Fatalf("the view's fields are %v, want %v", keys, want)
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Fatalf("the view lacks %s: %v", k, keys)
		}
	}
	// The row names the host, never the address: a receiver may put a token in its path or query,
	// and an audit row is never edited afterwards.
	if got := joined(f.log.take()); got != "webhook_create account:"+f.mine+" webhook:"+made.ID+" host:hooks.example.test:8443 ok" {
		t.Fatalf("audit:\n%s", got)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnEmptyFilterIsStoredAsAnEmptyList(t *testing.T) {
	f := newFixture(t)
	made, _ := f.create(t, "http://127.0.0.1:9/h")
	if b := mustJSON(t, made); !strings.Contains(string(b), `"events":[]`) || !strings.Contains(string(b), `"rotating_until":null`) {
		t.Fatalf("the view is %s", b)
	}
	if e, _ := f.st.GetWebhookEndpoint(context.Background(), f.mine, made.ID); e.Events != "[]" {
		t.Fatalf("stored events %q", e.Events)
	}
}

func TestRotatingKeepsTheOldSecretAcceptedForADay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, first := f.create(t, "https://hooks.example.test/rotate")
	f.log.take()
	second, until, err := f.svc.Rotate(ctx, f.mine, made.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second == first || !strings.HasPrefix(second, "whsec_") || until != now.Add(RotationWindow).UnixMilli() {
		t.Fatalf("rotated to %q until %d", second, until)
	}
	// Inside the window the view says a rotation is in flight; after it, it does not.
	*f.clock = now.Add(1000 * 1e6)
	if during := f.find(t, made.ID); during.RotatingUntil == nil || *during.RotatingUntil != until {
		t.Fatalf("during the window: %+v", during)
	}
	*f.clock = now.Add(RotationWindow + 1e6)
	if after := f.find(t, made.ID); after.RotatingUntil != nil {
		t.Fatalf("after the window: %+v", after)
	}
	if got := joined(f.log.take()); got != "webhook_rotate account:"+f.mine+" webhook:"+made.ID+" ok" {
		t.Fatalf("audit:\n%s", got)
	}
}

func TestAPausedEndpointRotates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/p")
	if err := f.svc.SetStatus(ctx, f.mine, made.ID, "paused"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Rotate(ctx, f.mine, made.ID); err != nil {
		t.Fatalf("a paused endpoint's rotation: %v", err)
	}
	if e := f.find(t, made.ID); e.Status != "paused" || e.RotatingUntil == nil {
		t.Fatalf("after rotating a paused endpoint: %+v", e)
	}
}

func TestAnEndpointPausesResumesWithACleanSlateAndIsRemoved(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	made, _ := f.create(t, "https://hooks.example.test/park")
	for range FailureLimit - 1 {
		if _, err := f.st.CountWebhookFailure(ctx, f.mine, made.ID, FailureLimit, 1); err != nil {
			t.Fatal(err)
		}
	}
	f.log.take()
	if err := f.svc.SetStatus(ctx, f.mine, made.ID, "paused"); err != nil {
		t.Fatal(err)
	}
	if e := f.find(t, made.ID); e.Status != "paused" || e.ConsecutiveFailures != FailureLimit-1 {
		t.Fatalf("paused: %+v", e)
	}
	// Resuming clears the count: an endpoint parked for being down and since fixed must not be one
	// failure from parked again.
	if err := f.svc.SetStatus(ctx, f.mine, made.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if e := f.find(t, made.ID); e.Status != "active" || e.ConsecutiveFailures != 0 {
		t.Fatalf("resumed: %+v", e)
	}
	if err := f.svc.Remove(ctx, f.mine, made.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Remove(ctx, f.mine, made.ID); !isNotFound(err) {
		t.Fatalf("a second delete: %v, want not_found", err)
	}
	subject := "account:" + f.mine + " webhook:" + made.ID
	want := strings.Join([]string{"webhook_pause " + subject + " ok", "webhook_resume " + subject + " ok",
		"webhook_delete " + subject + " ok", "webhook_delete " + subject + " not_found"}, "\n")
	if got := joined(f.log.take()); got != want {
		t.Fatalf("audit:\n%s\nwant:\n%s", got, want)
	}
}

func isNotFound(err error) bool {
	code, _ := refusal.Of(err)
	return code == "not_found"
}

// Building rule 3: every door's refusals. An endpoint that does not exist and another account's
// endpoint are both not found, and the other account's endpoint is left as it was; a malformed
// argument is a bad request; an unknown account is not found, never an empty list.
func TestEveryCallRefusesAMissingAnotherAccountsAndAMalformedTarget(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	theirs, _, err := f.svc.Create(ctx, f.theirs, "https://theirs.example.test/h", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.log.take()
	for _, id := range []string{"whe_nobody", theirs.ID} {
		calls := map[string]error{}
		_, _, calls["rotate"] = f.svc.Rotate(ctx, f.mine, id)
		calls["pause"] = f.svc.SetStatus(ctx, f.mine, id, "paused")
		calls["resume"] = f.svc.SetStatus(ctx, f.mine, id, "active")
		calls["remove"] = f.svc.Remove(ctx, f.mine, id)
		_, calls["deliveries"] = f.svc.ListDeliveries(ctx, f.mine, id, 0)
		for name, err := range calls {
			if code, detail := refusal.Of(err); code != "not_found" || detail != refusal.NotFoundDetail {
				t.Errorf("%s of %s: %s %q, want not_found", name, id, code, detail)
			}
		}
	}
	after, err := f.st.GetWebhookEndpoint(ctx, f.theirs, theirs.ID)
	if err != nil || after.Status != "active" || after.PreviousSealed != nil {
		t.Fatalf("the other account's endpoint changed: %+v %v", after, err)
	}
	// Refusals by the store's scope are audited under the caller's account, naming the id asked for.
	if got := joined(f.log.take()); strings.Count(got, " not_found") != 8 || !strings.Contains(got, "webhook_rotate account:"+f.mine+" webhook:"+theirs.ID+" not_found") {
		t.Fatalf("audit:\n%s", got)
	}

	mine, _ := f.create(t, "https://mine.example.test/h")
	f.log.take()
	if err := f.svc.SetStatus(ctx, f.mine, mine.ID, "parked"); !isBadRequest(err) {
		t.Errorf("an unknown status: %v, want bad_request", err)
	}
	if got, want := joined(f.log.take()), "webhook_status account:"+f.mine+" webhook:"+mine.ID+" bad_request"; got != want {
		t.Errorf("an unknown status is audited as %q, want %q", got, want)
	}
	if e := f.find(t, mine.ID); e.Status != "active" {
		t.Errorf("an unknown status changed the endpoint to %q", e.Status)
	}
	for _, limit := range []int{-1, deliveriesMax + 1} {
		if _, err := f.svc.ListDeliveries(ctx, f.mine, mine.ID, limit); !isBadRequest(err) {
			t.Errorf("a limit of %d: %v, want bad_request", limit, err)
		}
	}
	for name, call := range map[string]func() error{
		"create": func() error {
			_, _, err := f.svc.Create(ctx, "no-such-account", "https://x.example.test/", nil)
			return err
		},
		"list": func() error { _, err := f.svc.List(ctx, "no-such-account"); return err },
	} {
		if code, detail := refusal.Of(call()); code != "not_found" || detail != "unknown account" {
			t.Errorf("%s for an unknown account: %s %q, want not_found", name, code, detail)
		}
	}
	// The controls: the owner's own calls on its own endpoint go through.
	if _, _, err := f.svc.Rotate(ctx, f.mine, mine.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ListDeliveries(ctx, f.mine, mine.ID, deliveriesMax); err != nil {
		t.Fatal(err)
	}
	if l, err := f.svc.List(ctx, f.theirs); err != nil || len(l) != 1 || l[0].ID != theirs.ID {
		t.Fatalf("the other account lists %+v %v, want its own one", l, err)
	}
}

func isBadRequest(err error) bool {
	code, _ := refusal.Of(err)
	return code == "bad_request"
}

func TestTheListIsNewestFirstAndBounded(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range EndpointLimit + 1 {
		if err := f.st.InsertWebhookEndpoint(ctx, store.WebhookEndpoint{ID: "whe_" + string(rune('a'+i/26)) + string(rune('a'+i%26)),
			AccountID: f.mine, URL: "https://x.example.test/", Events: "[]", SecretSealed: []byte("s"),
			CreatedAt: int64(i), UpdatedAt: int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	l, err := f.svc.List(ctx, f.mine)
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != EndpointLimit || l[0].CreatedAt != EndpointLimit || l[len(l)-1].CreatedAt != 1 {
		t.Fatalf("listed %d, newest %d, oldest %d", len(l), l[0].CreatedAt, l[len(l)-1].CreatedAt)
	}
}

// An account has at most EndpointLimit endpoints: the next is a conflict, audited, and nothing is
// stored. The control: once one is removed, the next is taken.
func TestTheEndpointPastTheLimitIsAConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var first EndpointView
	for i := range EndpointLimit {
		v, _ := f.create(t, "https://hooks.example.test/"+strconv.Itoa(i))
		if i == 0 {
			first = v
		}
	}
	f.log.take()
	_, secret, err := f.svc.Create(ctx, f.mine, "https://hooks.example.test/one-more", nil)
	if code, detail := refusal.Of(err); code != "conflict" || secret != "" ||
		detail != "This identity has 100 endpoints, the most it can have. Remove one to add another." {
		t.Fatalf("the endpoint past the limit: %s %q (secret %q), want a conflict", code, detail, secret)
	}
	if got, want := joined(f.log.take()), "webhook_create account:"+f.mine+" endpoint_cap"; got != want {
		t.Fatalf("audit: %q, want %q", got, want)
	}
	if n, _ := f.st.CountWebhookEndpoints(ctx, f.mine); n != EndpointLimit {
		t.Fatalf("%d endpoints stored, want %d", n, EndpointLimit)
	}
	// Another account is not held to this one's count.
	if _, _, err := f.svc.Create(ctx, f.theirs, "https://theirs.example.test/h", nil); err != nil {
		t.Fatalf("another account's first endpoint: %v", err)
	}
	if err := f.svc.Remove(ctx, f.mine, first.ID); err != nil {
		t.Fatal(err)
	}
	f.create(t, "https://hooks.example.test/one-more")
}

// An account's first endpoint starts the dispatcher's cursor at the newest change, so the log
// written before it is not walked change by change; a later endpoint leaves the cursor where the
// dispatcher has it. An endpoint is still sent nothing from a second before it was added; the
// first one is also not sent a change written earlier in its own second.
func TestTheFirstEndpointStartsTheCursorAtTheNewestChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var last int64
	for i := range 3 {
		id, err := f.st.AppendChange(ctx, store.Change{AccountID: f.mine, Kind: "message", ThreadID: "th",
			At: f.clock.Unix() - 60, MsgID: "old" + strconv.Itoa(i), Direction: "in", MsgKind: "text"})
		if err != nil {
			t.Fatal(err)
		}
		last = id
	}
	f.create(t, "https://hooks.example.test/a")
	if got, _ := f.st.WebhookCursor(ctx, f.mine); got != last {
		t.Fatalf("the first endpoint left the cursor at %d, want the newest change %d", got, last)
	}
	if got, _ := f.st.WebhookCursor(ctx, f.theirs); got != 0 {
		t.Fatalf("another account's cursor moved to %d", got)
	}
	// The dispatcher has moved on; a second endpoint does not move it back, or on.
	if ok, _ := f.st.ClaimWebhookCursor(ctx, f.mine, last, last+5); !ok {
		t.Fatal("claim")
	}
	f.create(t, "https://hooks.example.test/b")
	if got, _ := f.st.WebhookCursor(ctx, f.mine); got != last+5 {
		t.Fatalf("a second endpoint moved the cursor to %d, want %d", got, last+5)
	}
}

// The cap holds under concurrent creates: two node processes on one store, each adding an endpoint
// to an account that has EndpointLimit-1, store exactly one and refuse the other. On PostgreSQL
// (read committed) the count alone would let both through; Create locks the account first. Each
// round frees the slot again, and every round must hold.
func TestTheCapHoldsUnderConcurrentCreates(t *testing.T) {
	for engine, handles := range sharedStores(t, 2) {
		t.Run(engine, func(t *testing.T) {
			ctx := context.Background()
			f := newFixtureOn(t, handles[0], newKeyring(t))
			other := New(handles[1], f.kr, f.log.audit)
			other.now = f.svc.now
			for i := range EndpointLimit - 1 {
				f.create(t, "https://hooks.example.test/"+strconv.Itoa(i))
			}
			f.log.take()
			for round := range 5 {
				var wg sync.WaitGroup
				start := make(chan struct{})
				made := make([]EndpointView, 2)
				errs := make([]error, 2)
				for k, svc := range []*Service{f.svc, other} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						made[k], _, errs[k] = svc.Create(ctx, f.mine, "https://hooks.example.test/race", nil)
					}()
				}
				close(start)
				wg.Wait()
				n, err := f.st.CountWebhookEndpoints(ctx, f.mine)
				if err != nil {
					t.Fatal(err)
				}
				refused := 0
				for _, err := range errs {
					if code, _ := refusal.Of(err); err != nil && code == "conflict" {
						refused++
					} else if err != nil {
						t.Fatalf("round %d: %v", round, err)
					}
				}
				if got := joined(f.log.take()); n != EndpointLimit || refused != 1 ||
					strings.Count(got, "webhook_create account:"+f.mine+" endpoint_cap") != 1 {
					t.Fatalf("round %d: %d endpoints stored, %d refused, audit %q; want %d and one endpoint_cap",
						round, n, refused, got, EndpointLimit)
				}
				for _, m := range made {
					if m.ID != "" {
						if err := f.svc.Remove(ctx, f.mine, m.ID); err != nil {
							t.Fatal(err)
						}
					}
				}
				f.log.take()
			}
		})
	}
}

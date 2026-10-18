package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
	} {
		if got := CheckEndpointURL(raw); got != want {
			t.Errorf("CheckEndpointURL(%q) = %q, want %q", raw, got, want)
		}
	}
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
	if got := joined(f.log.take()); strings.Count(got, "webhook_create account:"+f.mine+" bad_request") != 3 {
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
	if err := f.svc.SetStatus(ctx, f.mine, mine.ID, "parked"); !isBadRequest(err) {
		t.Errorf("an unknown status: %v, want bad_request", err)
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
	for i := range listLimit + 1 {
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
	if len(l) != listLimit || l[0].CreatedAt != listLimit || l[len(l)-1].CreatedAt != 1 {
		t.Fatalf("listed %d, newest %d, oldest %d", len(l), l[0].CreatedAt, l[len(l)-1].CreatedAt)
	}
}

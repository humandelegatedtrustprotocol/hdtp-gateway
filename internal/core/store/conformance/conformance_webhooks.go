package conformance

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// webhooks is the suite for the webhook endpoints, their delivery log, and the message a change row
// names (internal/services/webhooks).
func webhooks(t *testing.T, newStore Factory) {
	// Every write is scoped to the account: another account's endpoint answers as one that does
	// not exist, and is left as it was.
	t.Run("WebhookEndpointsAreScopedToTheirAccount", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wh-a", DisplayName: "A", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wh-b", DisplayName: "B", Algo: "p256"})
		e := store.WebhookEndpoint{ID: "whe_a", AccountID: a.ID, URL: "http://127.0.0.1:9000/hook", Events: `["message.received"]`,
			SecretSealed: []byte("sealed-1"), CreatedAt: 1000, UpdatedAt: 1000}
		if err := s.InsertWebhookEndpoint(ctx, e); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetWebhookEndpoint(ctx, a.ID, "whe_a")
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "active" || got.Failures != 0 || got.URL != e.URL || got.Events != e.Events ||
			string(got.SecretSealed) != "sealed-1" || got.PreviousSealed != nil || got.PreviousUntil != 0 || got.CreatedAt != 1000 {
			t.Fatalf("the endpoint did not come back as stored: %+v", got)
		}
		if _, err := s.GetWebhookEndpoint(ctx, b.ID, "whe_a"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another account's endpoint must be not found, got %v", err)
		}
		if l, err := s.ListWebhookEndpoints(ctx, b.ID, 100); err != nil || len(l) != 0 {
			t.Fatalf("another account lists %d endpoints (%v), want none", len(l), err)
		}
		for name, write := range map[string]func() (bool, error){
			"rotate": func() (bool, error) { return s.RotateWebhookSecret(ctx, b.ID, "whe_a", []byte("theirs"), 9, 9) },
			"pause":  func() (bool, error) { return s.PauseWebhookEndpoint(ctx, b.ID, "whe_a", 9) },
			"resume": func() (bool, error) { return s.ResumeWebhookEndpoint(ctx, b.ID, "whe_a", 9) },
			"clear":  func() (bool, error) { return s.ClearWebhookFailures(ctx, b.ID, "whe_a", 9) },
			"count":  func() (bool, error) { return s.CountWebhookFailure(ctx, b.ID, "whe_a", 1, 9) },
			"delete": func() (bool, error) { return s.DeleteWebhookEndpoint(ctx, b.ID, "whe_a") },
		} {
			if ok, err := write(); ok || err != nil {
				t.Fatalf("%s by another account: %v %v, want false and no error", name, ok, err)
			}
		}
		if after, _ := s.GetWebhookEndpoint(ctx, a.ID, "whe_a"); after.Status != "active" || after.Failures != 0 ||
			string(after.SecretSealed) != "sealed-1" || after.UpdatedAt != 1000 {
			t.Fatalf("another account's writes changed the endpoint: %+v", after)
		}
		// The control: the owning account's delete goes through, once.
		if ok, err := s.DeleteWebhookEndpoint(ctx, a.ID, "whe_a"); !ok || err != nil {
			t.Fatalf("the owner's delete: %v %v", ok, err)
		}
		if ok, err := s.DeleteWebhookEndpoint(ctx, a.ID, "whe_a"); ok || err != nil {
			t.Fatalf("a second delete: %v %v, want false", ok, err)
		}
	})

	t.Run("ARotationKeepsTheSecretItReplaces", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wh-rot", DisplayName: "A", Algo: "p256"})
		if err := s.InsertWebhookEndpoint(ctx, store.WebhookEndpoint{ID: "whe_r", AccountID: a.ID, URL: "https://x.example/h",
			Events: "[]", SecretSealed: []byte("s1"), CreatedAt: 1, UpdatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.RotateWebhookSecret(ctx, a.ID, "whe_r", []byte("s2"), 500, 2); !ok || err != nil {
			t.Fatalf("rotate: %v %v", ok, err)
		}
		got, _ := s.GetWebhookEndpoint(ctx, a.ID, "whe_r")
		if string(got.SecretSealed) != "s2" || string(got.PreviousSealed) != "s1" || got.PreviousUntil != 500 || got.UpdatedAt != 2 {
			t.Fatalf("after one rotation: %+v", got)
		}
		// A rotation during a rotation drops the oldest of three.
		if ok, err := s.RotateWebhookSecret(ctx, a.ID, "whe_r", []byte("s3"), 600, 3); !ok || err != nil {
			t.Fatalf("rotate again: %v %v", ok, err)
		}
		got, _ = s.GetWebhookEndpoint(ctx, a.ID, "whe_r")
		if string(got.SecretSealed) != "s3" || string(got.PreviousSealed) != "s2" || got.PreviousUntil != 600 {
			t.Fatalf("after a second rotation: %+v", got)
		}
	})

	t.Run("AFailureRunParksAtTheLimitAndResumingClearsIt", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wh-fail", DisplayName: "A", Algo: "p256"})
		if err := s.InsertWebhookEndpoint(ctx, store.WebhookEndpoint{ID: "whe_f", AccountID: a.ID, URL: "https://x.example/h",
			Events: "[]", SecretSealed: []byte("s"), CreatedAt: 1, UpdatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 3; i++ {
			if ok, err := s.CountWebhookFailure(ctx, a.ID, "whe_f", 3, int64(10+i)); !ok || err != nil {
				t.Fatalf("failure %d: %v %v", i, ok, err)
			}
			got, _ := s.GetWebhookEndpoint(ctx, a.ID, "whe_f")
			want := "active"
			if i == 3 {
				want = "paused"
			}
			if got.Failures != int64(i) || got.Status != want {
				t.Fatalf("after %d failures: %d %s, want %d %s", i, got.Failures, got.Status, i, want)
			}
		}
		if ok, err := s.ResumeWebhookEndpoint(ctx, a.ID, "whe_f", 20); !ok || err != nil {
			t.Fatalf("resume: %v %v", ok, err)
		}
		if got, _ := s.GetWebhookEndpoint(ctx, a.ID, "whe_f"); got.Status != "active" || got.Failures != 0 {
			t.Fatalf("resuming must clear the run: %+v", got)
		}
		_, _ = s.CountWebhookFailure(ctx, a.ID, "whe_f", 3, 21)
		if ok, err := s.ClearWebhookFailures(ctx, a.ID, "whe_f", 22); !ok || err != nil {
			t.Fatalf("clear: %v %v", ok, err)
		}
		if got, _ := s.GetWebhookEndpoint(ctx, a.ID, "whe_f"); got.Failures != 0 || got.UpdatedAt != 22 {
			t.Fatalf("a success must clear the run: %+v", got)
		}
		if ok, err := s.PauseWebhookEndpoint(ctx, a.ID, "whe_f", 23); !ok || err != nil {
			t.Fatalf("pause: %v %v", ok, err)
		}
		if got, _ := s.GetWebhookEndpoint(ctx, a.ID, "whe_f"); got.Status != "paused" {
			t.Fatalf("pause: %+v", got)
		}
	})

	t.Run("DeliveriesAreNewestFirstAndOutliveTheirEndpoint", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wh-log", DisplayName: "A", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wh-log-b", DisplayName: "B", Algo: "p256"})
		if err := s.InsertWebhookEndpoint(ctx, store.WebhookEndpoint{ID: "whe_l", AccountID: a.ID, URL: "https://x.example/h",
			Events: "[]", SecretSealed: []byte("s"), CreatedAt: 1, UpdatedAt: 1}); err != nil {
			t.Fatal(err)
		}
		for _, d := range []store.WebhookDelivery{
			{ID: "whd_1", AccountID: a.ID, EndpointID: "whe_l", EventID: "evt_1", EventType: "message.received", Status: "delivered", HTTPStatus: 200, LatencyMs: 5, Excerpt: "ok", CreatedAt: 100},
			{ID: "whd_2", AccountID: a.ID, EndpointID: "whe_l", EventID: "evt_2", EventType: "message.received", Status: "failed", LatencyMs: 7, Excerpt: "connection refused", CreatedAt: 200},
			{ID: "whd_3", AccountID: a.ID, EndpointID: "whe_l", EventID: "evt_3", EventType: "call.made", Status: "failed", HTTPStatus: 500, LatencyMs: 9, CreatedAt: 300},
		} {
			if err := s.InsertWebhookDelivery(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.ListWebhookDeliveries(ctx, a.ID, "whe_l", 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].ID != "whd_3" || got[1].ID != "whd_2" {
			t.Fatalf("want the newest two, newest first: %+v", got)
		}
		if got[1].HTTPStatus != 0 || got[1].Excerpt != "connection refused" || got[0].HTTPStatus != 500 || got[0].Excerpt != "" {
			t.Fatalf("an attempt with no answer must read back with no status: %+v", got)
		}
		if l, _ := s.ListWebhookDeliveries(ctx, b.ID, "whe_l", 50); len(l) != 0 {
			t.Fatalf("another account reads %d deliveries", len(l))
		}
		if ok, _ := s.DeleteWebhookEndpoint(ctx, a.ID, "whe_l"); !ok {
			t.Fatal("delete")
		}
		if l, _ := s.ListWebhookDeliveries(ctx, a.ID, "whe_l", 50); len(l) != 3 {
			t.Fatalf("the log must outlive its endpoint: %d rows", len(l))
		}
	})

	t.Run("AChangeRowCarriesItsMessage", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		want := store.Change{AccountID: "acct", Kind: "message", ThreadID: "th", ContactFpr: "sha256:c", At: 7,
			MsgID: "m1", Direction: "in", MsgKind: "media"}
		id, err := s.AppendChange(ctx, want)
		if err != nil {
			t.Fatal(err)
		}
		want.ID = id
		all, err := s.ChangesAfter(ctx, 0, 10)
		if err != nil || len(all) != 1 || all[0] != want {
			t.Fatalf("ChangesAfter: %+v %v, want %+v", all, err, want)
		}
		mine, err := s.AccountChangesAfter(ctx, "acct", 0, 10)
		if err != nil || len(mine) != 1 || mine[0] != want {
			t.Fatalf("AccountChangesAfter: %+v %v, want %+v", mine, err, want)
		}
	})

	// The dispatcher's cursor: an account's first claim and every later one move it only from the id
	// the claimant read, so a second claimant of the same change is refused and nothing moves.
	t.Run("ACursorIsClaimedOnceFromTheIdItWasReadAt", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		a, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wc-a", DisplayName: "A", Algo: "p256"})
		b, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: "wc-b", DisplayName: "B", Algo: "p256"})
		if got, err := s.WebhookCursor(ctx, a.ID); got != 0 || err != nil {
			t.Fatalf("an unclaimed cursor: %d %v, want 0", got, err)
		}
		claim := func(acct string, from, to int64, want bool) {
			t.Helper()
			if ok, err := s.ClaimWebhookCursor(ctx, acct, from, to); ok != want || err != nil {
				t.Fatalf("claim %s %d->%d: %v %v, want %v", acct, from, to, ok, err, want)
			}
		}
		claim(a.ID, 0, 5, true)
		claim(a.ID, 0, 6, false) // a second first claim
		claim(a.ID, 4, 6, false) // from an id it is not at
		if got, _ := s.WebhookCursor(ctx, a.ID); got != 5 {
			t.Fatalf("the refused claims moved the cursor to %d", got)
		}
		claim(a.ID, 5, 9, true)
		claim(a.ID, 5, 9, false) // the same claim, made again
		if got, _ := s.WebhookCursor(ctx, a.ID); got != 9 {
			t.Fatalf("the cursor is at %d, want 9", got)
		}
		// Each account has its own.
		if got, _ := s.WebhookCursor(ctx, b.ID); got != 0 {
			t.Fatalf("another account's cursor is at %d", got)
		}
		claim(b.ID, 0, 2, true)
		if got, _ := s.WebhookCursor(ctx, a.ID); got != 9 {
			t.Fatalf("another account's claim moved this one to %d", got)
		}
	})

	t.Run("TheAccountsWithAnEndpointActiveOrPausedAreListed", func(t *testing.T) {
		s := migrated(t, newStore)
		ctx := context.Background()
		if l, err := s.WebhookAccounts(ctx); len(l) != 0 || err != nil {
			t.Fatalf("no endpoints: %v %v", l, err)
		}
		var ids []string
		for _, slug := range []string{"wl-a", "wl-b", "wl-none"} {
			acct, _ := s.CreateAccount(ctx, store.CreateAccountParams{Slug: slug, DisplayName: slug, Algo: "p256"})
			ids = append(ids, acct.ID)
		}
		for i, e := range []store.WebhookEndpoint{
			{ID: "whe_1", AccountID: ids[0]}, {ID: "whe_2", AccountID: ids[0]}, {ID: "whe_3", AccountID: ids[1]},
		} {
			e.URL, e.Events, e.SecretSealed, e.CreatedAt, e.UpdatedAt = "http://127.0.0.1/", "[]", []byte{1}, int64(i), int64(i)
			if err := s.InsertWebhookEndpoint(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		if ok, _ := s.PauseWebhookEndpoint(ctx, ids[1], "whe_3", 9); !ok {
			t.Fatal("pause")
		}
		got, err := s.WebhookAccounts(ctx)
		want := []string{ids[0], ids[1]}
		slices.Sort(want)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("accounts with an endpoint: %v %v, want %v (once each, a paused one included)", got, err, want)
		}
	})
}

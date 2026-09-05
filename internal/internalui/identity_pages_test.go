package internalui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/identity"
)

func identityHarness(t *testing.T, rotate func(context.Context, string, time.Duration) (RotateResult, error)) (*http.ServeMux, *[]string) {
	t.Helper()
	var audits []string
	mux := http.NewServeMux()
	MountIdentityPages(mux, IdentityDeps{
		Accounts: func(context.Context) ([]store.Account, error) {
			return []store.Account{{ID: "acct-1", Slug: "alice", DisplayName: "Alice", Algo: "p256", Fingerprint: "sha256:aaa"}}, nil
		},
		Rotate: rotate,
		Audit:  func(a, r, o string) { audits = append(audits, a+"/"+o) },
	})
	return mux, &audits
}

func post(mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/identity/rotate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// The guard is the point. Rotation is not undoable: every active contact is sent
// an update_contact signed by the OLD key, and any contact that never receives it
// must re-pin by hand. A misclick must not be able to start that.
func TestRotationRequiresTypingTheSlug(t *testing.T) {
	called := false
	mux, audits := identityHarness(t, func(context.Context, string, time.Duration) (RotateResult, error) {
		called = true
		return RotateResult{}, nil
	})

	for _, wrong := range []string{"", "Alice", "alic", "yes", "acct-1"} {
		called = false
		w := post(mux, url.Values{"account_id": {"acct-1"}, "confirm": {wrong}})
		if called {
			t.Fatalf("confirm=%q started a rotation; only the exact slug may", wrong)
		}
		if !strings.Contains(w.Body.String(), "Nothing was rotated") {
			t.Errorf("confirm=%q did not tell the owner nothing happened", wrong)
		}
	}
	for _, a := range *audits {
		if strings.HasSuffix(a, "/not_confirmed") {
			return
		}
	}
	t.Error("a refused rotation was not audited")
}

func TestRotationRunsWhenConfirmed(t *testing.T) {
	var gotGrace time.Duration
	mux, _ := identityHarness(t, func(_ context.Context, id string, g time.Duration) (RotateResult, error) {
		gotGrace = g
		return RotateResult{NewFpr: "sha256:new", Notified: 3, GraceUntil: time.Unix(1800000000, 0)}, nil
	})
	w := post(mux, url.Values{"account_id": {"acct-1"}, "confirm": {"alice"}, "grace": {"48h"}})
	body := w.Body.String()
	if !strings.Contains(body, "sha256:new") {
		t.Errorf("the new fingerprint was not shown: %s", body)
	}
	if gotGrace != 48*time.Hour {
		t.Errorf("grace reached the rotator as %v, want 48h", gotGrace)
	}
}

// An incomplete fan-out is the NORMAL case when a contact is offline. Rounding it
// up to success would leave the owner believing everyone holds the new key, and a
// contact that never re-pins is lost when the old key expires (§3.9 step 5).
func TestAnIncompleteFanoutIsReportedNotRoundedUp(t *testing.T) {
	mux, _ := identityHarness(t, func(context.Context, string, time.Duration) (RotateResult, error) {
		return RotateResult{NewFpr: "sha256:new", Notified: 2, Failed: 3, GraceUntil: time.Unix(1800000000, 0)}, nil
	})
	body := post(mux, url.Values{"account_id": {"acct-1"}, "confirm": {"alice"}}).Body.String()
	if !strings.Contains(body, "3 could not be reached") {
		t.Errorf("the failed contacts were not reported: %s", body)
	}
	if !strings.Contains(body, "re-run") {
		t.Errorf("the owner was not told they can resume the fan-out: %s", body)
	}
}

func TestABadGraceIsRefusedBeforeRotating(t *testing.T) {
	called := false
	mux, _ := identityHarness(t, func(context.Context, string, time.Duration) (RotateResult, error) {
		called = true
		return RotateResult{}, nil
	})
	body := post(mux, url.Values{"account_id": {"acct-1"}, "confirm": {"alice"}, "grace": {"soon"}}).Body.String()
	if called {
		t.Fatal("an unparseable grace period still rotated the key")
	}
	if !strings.Contains(body, "Nothing was rotated") {
		t.Errorf("the owner was not told the rotation did not happen: %s", body)
	}
}

func TestUnknownAccountIsRefused(t *testing.T) {
	called := false
	mux, _ := identityHarness(t, func(context.Context, string, time.Duration) (RotateResult, error) {
		called = true
		return RotateResult{}, nil
	})
	post(mux, url.Values{"account_id": {"nope"}, "confirm": {"alice"}})
	if called {
		t.Fatal("rotation ran for an account that does not exist")
	}
}

// The owner typing 0 means "no grace period", and it must reach the rotator as
// the explicit sentinel — not as a plain 0, which the rotator reads as "use the
// default". A negative value is still refused.
func TestZeroGraceIsAnImmediateRotationAndNegativeIsRefused(t *testing.T) {
	var got time.Duration
	mux, _ := identityHarness(t, func(_ context.Context, _ string, g time.Duration) (RotateResult, error) {
		got = g
		return RotateResult{NewFpr: "sha256:new", Notified: 2, Failed: 1, GraceUntil: time.Unix(1800000000, 0), Immediate: g == identity.GraceImmediate}, nil
	})
	body := post(mux, url.Values{"account_id": {"acct-1"}, "confirm": {"alice"}, "grace": {"0"}}).Body.String()
	if got != identity.GraceImmediate {
		t.Fatalf("a typed 0 reached the rotator as %v, want GraceImmediate", got)
	}
	if !strings.Contains(body, "retired") || !strings.Contains(body, "lost") {
		t.Fatalf("an immediate rotation must say the old key is gone and unreached contacts are lost; got %s", body)
	}
	got = 0
	body = post(mux, url.Values{"account_id": {"acct-1"}, "confirm": {"alice"}, "grace": {"-5m"}}).Body.String()
	if got != 0 || !strings.Contains(body, "Nothing was rotated") {
		t.Fatalf("a negative grace rotated the key or was not refused: got=%v body=%s", got, body)
	}
}

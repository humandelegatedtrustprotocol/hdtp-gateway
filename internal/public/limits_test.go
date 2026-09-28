package public

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A clock this test moves, and a limiter on it.
func onClock(t *testing.T) (*Limiter, *time.Time) {
	t.Helper()
	clock := time.Unix(1756000000, 0)
	return NewLimiter(func() time.Time { return clock }), &clock
}

// The bucket arithmetic (PACT §12): a new caller holds the burst, spends it at once, is refused
// with the whole seconds until one call has dripped back, and refills at the rate, never past the
// burst.
func TestBucketArithmetic(t *testing.T) {
	lim, clock := onClock(t)
	key := LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:x"}
	for i := range ContactBurst {
		if ok, _ := lim.Allow(key); !ok {
			t.Fatalf("call %d refused inside the burst of %d", i+1, ContactBurst)
		}
	}
	ok, retry := lim.Allow(key)
	if ok {
		t.Fatalf("call %d allowed past the burst of %d", ContactBurst+1, ContactBurst)
	}
	if retry != time.Second {
		t.Fatalf("retry_after %v; one call a second is back in 1 s", retry)
	}
	// Half a second is half a call: still refused, still 1 s (rounded up, at least one).
	*clock = clock.Add(500 * time.Millisecond)
	if ok, retry := lim.Allow(key); ok || retry != time.Second {
		t.Fatalf("half a token spent a call (ok=%v retry=%v)", ok, retry)
	}
	*clock = clock.Add(500 * time.Millisecond)
	if ok, _ := lim.Allow(key); !ok {
		t.Fatal("a second later the call that dripped back was refused")
	}
	// An idle hour refills to the burst and no further.
	*clock = clock.Add(time.Hour)
	for i := range ContactBurst {
		if ok, _ := lim.Allow(key); !ok {
			t.Fatalf("call %d refused after an idle hour", i+1)
		}
	}
	if ok, _ := lim.Allow(key); ok {
		t.Fatal("an idle hour banked more than the burst")
	}
	if got := RetryAfterSeconds(RetryAfter(0.5, GuestBucket)); got != 180 {
		t.Fatalf("a guest half a call short waits %d s; at 10 an hour that is 180", got)
	}
	// A wait that is not whole seconds is rounded UP: at 0.3 calls a second one call is 3.33 s
	// away, and a caller told 3 is refused again.
	if got := RetryAfter(0, Bucket{Rate: 0.3, Burst: 1}); got != 4*time.Second {
		t.Fatalf("a 3.33 s wait is told as %v, want 4 s", got)
	}
}

// The owner's rule: every contact an account may hold calls at once, one a second each, and none
// is refused. N is the enforced aggregate (IdentityCallsPerSecond of the default cap), so a lower
// measured capacity lowers N here rather than failing silently.
func TestEveryContactAtItsRateIsServed(t *testing.T) {
	lim, clock := onClock(t)
	n := IdentityCallsPerSecond(DefaultContactCap)
	if n != min(DefaultContactCap, NodeCapacityPerSecond) {
		t.Fatalf("the aggregate for %d contacts is %d", DefaultContactCap, n)
	}
	for second := range 30 {
		for i := range n {
			k := LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: fmt.Sprintf("sha256:c%d", i)}
			if ok, retry := lim.Allow(k); !ok {
				t.Fatalf("second %d: contact %d of %d refused (retry %v)", second, i, n, retry)
			}
		}
		*clock = clock.Add(time.Second)
	}
}

// One more contact than the aggregate, in the same second, is refused by the aggregate — with a
// seconds-scale retry_after — and its own bucket is not spent by the refusal.
func TestTheAggregateHolds(t *testing.T) {
	lim, _ := onClock(t)
	lim.ContactCap = func(string) int { return 3 }
	for i := range 3 {
		if ok, _ := lim.Allow(LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: fmt.Sprintf("sha256:c%d", i)}); !ok {
			t.Fatalf("contact %d refused inside the aggregate", i)
		}
	}
	late := LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:late"}
	ok, retry := lim.Allow(late)
	if ok {
		t.Fatal("a fourth contact in one second passed an aggregate of 3/s")
	}
	if retry != time.Second {
		t.Fatalf("aggregate retry_after %v, want 1 s", retry)
	}
	// Another account's aggregate is its own.
	if ok, _ := lim.Allow(LimitKey{Kind: KindContact, AccountID: "b", Fingerprint: "sha256:late"}); !ok {
		t.Fatal("one account's contacts spent another account's aggregate")
	}
	// The refusal spent nothing: late's own bucket is still full once the aggregate refills.
	if st := lim.state["contact\x00a\x00sha256:late"]; st != nil {
		t.Fatalf("a refused call wrote the contact's bucket: %+v", st)
	}
}

// Guests keep the ten an hour per root and address; the address alone has sixty.
func TestGuestAndSourceBudgets(t *testing.T) {
	lim, clock := onClock(t)
	g1 := LimitKey{Kind: KindGuest, AccountID: "a", Fingerprint: "sha256:g", IP: "1.2.3.4"}
	for i := range GuestCallsPerHour {
		if ok, _ := lim.Allow(g1); !ok {
			t.Fatalf("guest call %d refused early", i+1)
		}
	}
	ok, retry := lim.Allow(g1)
	if ok {
		t.Fatal("guest call 11 allowed")
	}
	if retry != 6*time.Minute {
		t.Fatalf("guest retry_after %v; at 10 an hour one call is back in 360 s", retry)
	}
	g2 := g1
	g2.IP = "5.6.7.8"
	if ok, _ := lim.Allow(g2); !ok {
		t.Fatal("distinct IP shares the budget")
	}
	g3 := g1
	g3.Fingerprint = "sha256:other"
	if ok, _ := lim.Allow(g3); !ok {
		t.Fatal("distinct key shares the budget")
	}
	src := LimitKey{Kind: KindSource, AccountID: "a", IP: "9.9.9.9"}
	for i := range GuestSourceCallsPerHour {
		if ok, _ := lim.Allow(src); !ok {
			t.Fatalf("source call %d refused inside %d", i+1, GuestSourceCallsPerHour)
		}
	}
	if ok, retry := lim.Allow(src); ok || retry != time.Minute {
		t.Fatalf("source call %d: ok=%v retry=%v, want refused for 60 s", GuestSourceCallsPerHour+1, ok, retry)
	}
	// Nothing proven and no address: one shared bucket, not an unmetered path.
	bare := LimitKey{Kind: KindSource, AccountID: "a"}
	for range GuestSourceCallsPerHour {
		lim.Allow(bare)
	}
	if ok, _ := lim.Allow(bare); ok {
		t.Fatal("a caller with no address and no key is unmetered")
	}
	*clock = clock.Add(time.Minute)
	if ok, _ := lim.Allow(src); !ok {
		t.Fatal("a minute later the source's call that dripped back was refused")
	}
}

// What an account sends: to a contact at the contact's rate and within the aggregate, to anybody
// else twenty an hour.
func TestOutboundBudgets(t *testing.T) {
	lim, _ := onClock(t)
	for i := range ContactBurst {
		if ok, _ := lim.AllowOut("a", "sha256:friend", true); !ok {
			t.Fatalf("call %d to a contact refused inside the burst", i+1)
		}
	}
	if ok, retry := lim.AllowOut("a", "sha256:friend", true); ok || retry != time.Second {
		t.Fatalf("call past the burst to one contact: ok=%v retry=%v", ok, retry)
	}
	for i := range StrangerCallsOutPerHour {
		if ok, _ := lim.AllowOut("a", fmt.Sprintf("sha256:s%d", i), false); !ok {
			t.Fatalf("request %d to a stranger refused inside %d an hour", i+1, StrangerCallsOutPerHour)
		}
	}
	if ok, retry := lim.AllowOut("a", "sha256:one-more", false); ok || retry != 3*time.Minute {
		t.Fatalf("stranger call %d: ok=%v retry=%v, want refused for 180 s", StrangerCallsOutPerHour+1, ok, retry)
	}
	if ok, _ := lim.AllowOut("b", "sha256:one-more", false); !ok {
		t.Fatal("one account's stranger calls spent another's")
	}
	// Outbound and inbound are separate buckets.
	if ok, _ := lim.Allow(LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:friend"}); !ok {
		t.Fatal("calls out spent the contact's budget for calling in")
	}
}

// get_card advertises what the limiter enforces, read from the same buckets.
func TestLimitsAreTheEnforcedOnes(t *testing.T) {
	for _, cap := range []int{1, 100, DefaultContactCap, 12_500} {
		l := LimitsFor(cap)
		if l.IdentityCallsPerSecond != int(IdentityBucket(cap).Rate) || l.IdentityCallsPerSecond != min(cap, NodeCapacityPerSecond) {
			t.Errorf("cap %d advertises %d/s", cap, l.IdentityCallsPerSecond)
		}
		if l.ContactCallsPerSecond != 1 || l.ContactBurst != 10 || l.GuestCallsPerHour != 10 || l.GuestSourceCallsPerHour != 60 {
			t.Errorf("cap %d advertises %+v", cap, l)
		}
	}
	// And the advertised contact figures ARE the bucket: a burst's worth passes, one more does not.
	lim, _ := onClock(t)
	lim.ContactCap = func(string) int { return 7 }
	adv := LimitsFor(7)
	for i := range adv.IdentityCallsPerSecond {
		if ok, _ := lim.Allow(LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: fmt.Sprintf("sha256:%d", i)}); !ok {
			t.Fatalf("advertised %d/s, refused call %d", adv.IdentityCallsPerSecond, i+1)
		}
	}
	if ok, _ := lim.Allow(LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:extra"}); ok {
		t.Fatalf("advertised %d/s, served one more", adv.IdentityCallsPerSecond)
	}
}

func TestBodyCap(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, `{"code":"too_large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(200)
	})
	h := CapBody(inner, 1024)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", 2048))))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d, want 413", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("POST", "/", strings.NewReader("small")))
	if rr2.Code != 200 {
		t.Fatalf("small body: %d", rr2.Code)
	}
}

// A guest is budgeted per root AND address, so an attacker who varies either mints a fresh bucket
// every call. Buckets that have refilled carry nothing and are dropped, so the map is bounded by
// who called lately, not by everyone who ever did.
func TestLimiterDoesNotGrowWithoutBound(t *testing.T) {
	lim, clock := onClock(t)
	for i := range 500 {
		lim.Allow(LimitKey{Kind: KindGuest, AccountID: "a", Fingerprint: fmt.Sprintf("sha256:k%d", i), IP: fmt.Sprintf("10.0.%d.%d", i/256, i%256)})
	}
	if lim.Size() != 500 {
		t.Fatalf("precondition: tracking %d of 500 buckets", lim.Size())
	}
	// Six minutes refills one guest call — each of those holds its burst again.
	*clock = clock.Add(6*time.Minute + time.Second)
	live := LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:live"}
	lim.Allow(live)
	if lim.Size() != 2 {
		t.Errorf("refilled buckets still tracked: %d remain, want 2 (the live contact and the aggregate)", lim.Size())
	}
	// A sweep does not drop a bucket that is still spent: drain a guest, let a sweep fall due while
	// it has refilled a sixth of a call, and it is still refused.
	g := LimitKey{Kind: KindGuest, AccountID: "a", Fingerprint: "sha256:spent", IP: "10.9.9.9"}
	for range GuestCallsPerHour {
		lim.Allow(g)
	}
	*clock = clock.Add(limitSweepEvery)
	lim.Allow(LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:other"}) // sweeps
	if ok, _ := lim.Allow(g); ok {
		t.Error("the sweep forgot a bucket that was still spent")
	}
}

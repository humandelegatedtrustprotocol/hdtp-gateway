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

func TestContactRateLimit60PerHour(t *testing.T) {
	clock := time.Unix(1756000000, 0)
	lim := NewLimiter(func() time.Time { return clock })
	key := LimitKey{Kind: KindContact, AccountID: "a", Fingerprint: "sha256:x"}
	for i := 0; i < 60; i++ {
		if ok, _ := lim.Allow(key); !ok {
			t.Fatalf("call %d refused before the limit", i)
		}
	}
	ok, retry := lim.Allow(key)
	if ok {
		t.Fatal("61st call within the hour allowed")
	}
	if retry <= 0 || retry > time.Hour {
		t.Fatalf("retry_after out of range: %v", retry)
	}
	// window slides: an hour later the same key is fresh
	clock = clock.Add(time.Hour + time.Second)
	if ok, _ := lim.Allow(key); !ok {
		t.Fatal("call after window refused")
	}
}

func TestGuestRateLimit10PerHourPerIPAndKey(t *testing.T) {
	clock := time.Unix(1756000000, 0)
	lim := NewLimiter(func() time.Time { return clock })
	g1 := LimitKey{Kind: KindGuest, AccountID: "a", Fingerprint: "sha256:g", IP: "1.2.3.4"}
	for i := 0; i < 10; i++ {
		if ok, _ := lim.Allow(g1); !ok {
			t.Fatalf("guest call %d refused early", i)
		}
	}
	if ok, _ := lim.Allow(g1); ok {
		t.Fatal("11th guest call allowed")
	}
	// different IP or key = different budget
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

// A guest is budgeted per IP AND key, so an attacker who varies either mints a
// fresh entry every call. Pruning happens on touch and never revisits a key
// nobody uses again, so the map grew for as long as the node ran — slowly under
// honest traffic, as fast as you like under a scanner.
func TestLimiterDoesNotGrowWithoutBound(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := NewLimiter(clock)

	for i := 0; i < 500; i++ {
		l.Allow(LimitKey{Kind: KindGuest, Fingerprint: fmt.Sprintf("sha256:k%d", i), IP: fmt.Sprintf("10.0.%d.%d", i/256, i%256)})
	}
	if l.Size() != 500 {
		t.Fatalf("precondition: tracking %d of 500 keys", l.Size())
	}
	// A window later every one of those has expired. One live caller is enough
	// to trigger the sweep; nothing else ever touches the dead keys.
	now = now.Add(limitWindow + time.Minute)
	l.Allow(LimitKey{Kind: KindContact, Fingerprint: "sha256:live"})
	if l.Size() != 1 {
		t.Errorf("expired keys still tracked: %d remain, want 1", l.Size())
	}

	// And the sweep does not evict a caller whose window is still open. The
	// first version of this check advanced the clock only half a window, so no
	// sweep ran at all and the assertion held vacuously. Force a real sweep —
	// a full interval since the last one — while the live caller's NEWEST hit
	// is inside the new cutoff: a sweep keyed on anything but last-hit recency
	// (first hit, insertion time) evicts the caller and fails here.
	live := LimitKey{Kind: KindContact, Fingerprint: "sha256:live"}
	now = now.Add(limitWindow - time.Minute)                          // still before the next sweep is due
	l.Allow(live)                                                     // newest hit lands just inside the coming window
	now = now.Add(2 * time.Minute)                                    // a full interval since the last sweep
	l.Allow(LimitKey{Kind: KindContact, Fingerprint: "sha256:other"}) // triggers it
	if l.Size() != 2 {
		t.Errorf("the sweep mishandled a live caller: %d keys, want 2 (live + other)", l.Size())
	}
	// The live caller's budget must also still count its surviving hit.
	if ok, _ := l.Allow(live); !ok {
		t.Error("the sweep corrupted a live caller's window")
	}
}

// PACT §12's caps are defaults, not a ceiling: two busy agents can legitimately
// exceed 60 calls an hour, and an operator who cannot raise the number has to
// choose between recompiling and being throttled.
func TestLimiterBudgetIsConfigurable(t *testing.T) {
	now := time.Now()
	l := NewLimiter(func() time.Time { return now })
	l.Budget = func(k LimitKey) int {
		if k.Kind == KindContact {
			return 2
		}
		return 0 // guests keep the documented cap
	}
	k := LimitKey{Kind: KindContact, Fingerprint: "sha256:a"}
	for i := 0; i < 2; i++ {
		if ok, _ := l.Allow(k); !ok {
			t.Fatalf("call %d refused inside the configured budget", i+1)
		}
	}
	if ok, retry := l.Allow(k); ok || retry <= 0 {
		t.Errorf("the configured budget was not enforced: ok=%v retry=%v", ok, retry)
	}

	// An answer at or below zero means the default, so a bad row cannot open
	// the gate — it restores PACT §12's number rather than removing the cap.
	g := LimitKey{Kind: KindGuest, Fingerprint: "sha256:b", IP: "10.0.0.1"}
	for i := 0; i < 10; i++ {
		if ok, _ := l.Allow(g); !ok {
			t.Fatalf("guest call %d refused inside the documented cap", i+1)
		}
	}
	if ok, _ := l.Allow(g); ok {
		t.Error("a zero budget removed the guest cap instead of restoring the default")
	}
}

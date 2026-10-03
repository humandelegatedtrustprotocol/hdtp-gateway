package limits_test

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
)

// Arbitrary numbers, unlike the defaults, so nothing here passes by agreeing with them by accident.
var testRules = Rules{
	ContactCallsPerSecond: 2, ContactBurst: 5, IdentityCapacityPerSecond: 7, GuestCallsPerHour: 3,
	GuestSourceCallsPerHour: 4, StrangerCallsOutPerHour: 6, IntegrationCallsPerHour: 8,
	GuestTotalCallsPerHour: 9, PendingInCap: 2,
}

func TestEveryKindOfChargeIsLetThroughFreshAndRefusedOnceSpentAndAnotherIdentityIsUntouched(t *testing.T) {
	s := limitstest.Start(t, testRules)
	ctx := context.Background()
	now := time.UnixMilli(1_790_000_000_000)
	cases := []struct {
		charge Charge
		burst  int
		bucket string
	}{
		{ContactIn("sha256:A", 500), 5, "contact:sha256:A"},
		{GuestIn("sha256:G", "203.0.113.9", true), 3, "guest:sha256:G:203.0.113.9"},
		{GuestIn("", "203.0.113.9", true), 4, "source:203.0.113.9"},
		{GuestIn("sha256:H", "", false), 3, "guest:sha256:H"},
		{ContactOut("sha256:A", 500), 5, "out:contact:sha256:A"},
		{StrangerOut(), 6, "out:stranger"},
	}
	for _, c := range cases {
		for i := 0; i < c.burst; i++ {
			d, err := s.Decide(ctx, "acc-1", []Charge{c.charge}, "", now)
			if err != nil || !d.Allowed {
				t.Fatalf("%s call %d: %+v %v", c.charge.Kind(), i+1, d, err)
			}
		}
		d, err := s.Decide(ctx, "acc-1", []Charge{c.charge}, "", now)
		if err != nil || d.Allowed || d.RefusedBy != c.bucket || !d.Countable || d.RetryAfter < time.Second {
			t.Fatalf("%s past its burst: %+v %v (want refused by %s with a wait)", c.charge.Kind(), d, err, c.bucket)
		}
		if d2, err := s.Decide(ctx, "acc-2", []Charge{c.charge}, "", now); err != nil || !d2.Allowed {
			t.Fatalf("%s for another identity: %+v %v", c.charge.Kind(), d2, err)
		}
	}
	// The pending cap counts rows and no wait refills it.
	if d, err := s.Decide(ctx, "acc-1", []Charge{PendingIn(1)}, "", now); err != nil || !d.Allowed {
		t.Fatalf("pending_in under the cap: %+v %v", d, err)
	}
	d, err := s.Decide(ctx, "acc-1", []Charge{PendingIn(2)}, "", now)
	if err != nil || d.Allowed || d.RefusedBy != "pending_in" || d.Countable || d.RetryAfter != 0 {
		t.Fatalf("pending_in at the cap: %+v %v", d, err)
	}
}

func TestTheRulesAreTheSidecarsAndAreReadOnce(t *testing.T) {
	s := limitstest.Start(t, testRules)
	r, err := s.Rules(context.Background())
	if err != nil || r != testRules {
		t.Fatalf("rules: %+v %v", r, err)
	}
}

func TestASidecarThatIsDownIsUnavailableAndOneThatComesBackIsReconnectedTo(t *testing.T) {
	s := limitstest.Start(t, testRules)
	ctx := context.Background()
	now := time.Now()
	if d, err := s.Decide(ctx, "acc-1", []Charge{StrangerOut()}, "", now); err != nil || !d.Allowed {
		t.Fatalf("before: %+v %v", d, err)
	}
	s.Stop()
	c := s.Client
	c.Timeout = 500 * time.Millisecond
	_, err := c.Decide(ctx, "acc-1", []Charge{StrangerOut()}, "", now)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("with the sidecar down, want ErrUnavailable, got %v", err)
	}
	if _, err := c.Probe(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("probe with the sidecar down: %v", err)
	}
	s.Restart(t)
	// The kept connection died with the old process; the next exchange dials again by itself.
	d, err := c.Decide(ctx, "acc-1", []Charge{StrangerOut()}, "", now)
	if err != nil || !d.Allowed {
		t.Fatalf("after the restart: %+v %v", d, err)
	}
}

func TestAZeroChargeIsTheCallersMistakeNotTheSidecars(t *testing.T) {
	for name, charges := range map[string][]Charge{"a zero charge": {{}}, "no charge": nil, "a zero charge after a good one": {StrangerOut(), {}}} {
		if _, err := New("/nonexistent/limits.sock").Decide(context.Background(), "acc-1", charges, "", time.Now()); err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s is a caller's mistake, not the sidecar's: %v", name, err)
		}
	}
}

// A guest's call after the open is two charges, its own bucket and the account's guest total, spent
// together or not at all; the check before the open asks the total without spending it, and lets a
// source through that a proven contact's call came from.
func TestTheGuestTotalIsSpentWithTheGuestAndAskedBeforeTheOpenWithoutSpending(t *testing.T) {
	s := limitstest.Start(t, testRules)
	ctx := context.Background()
	now := time.UnixMilli(1_790_000_000_000)
	total := int(testRules.GuestTotalCallsPerHour)
	for i := 0; i < total; i++ {
		// Each guest a root of its own, so the total is what runs out.
		d, err := s.Decide(ctx, "acc-1", []Charge{GuestIn(fmt.Sprintf("sha256:g%d", i), "203.0.113.1", true), GuestTotal()}, "", now)
		if err != nil || !d.Allowed {
			t.Fatalf("guest %d: %+v %v", i, d, err)
		}
	}
	d, err := s.Decide(ctx, "acc-1", []Charge{GuestIn("sha256:late", "203.0.113.1", true), GuestTotal()}, "", now)
	if err != nil || d.Allowed || d.RefusedBy != "guest-total" || d.RetryAfter < time.Second {
		t.Fatalf("a guest past the total: %+v %v", d, err)
	}
	// Refused by the total, its own bucket untouched: that root still has its whole guest budget.
	for i := 0; i < int(testRules.GuestCallsPerHour); i++ {
		if d, err := s.Decide(ctx, "acc-1", []Charge{GuestIn("sha256:late", "203.0.113.1", true)}, "", now); err != nil || !d.Allowed {
			t.Fatalf("the guest the total refused spent its own bucket: call %d %+v %v", i+1, d, err)
		}
	}
	// Before the open: an unknown source is refused with the total's wait, and asking spends nothing.
	for i := 0; i < 3; i++ {
		d, err := s.Admit(ctx, "acc-1", "203.0.113.2", now)
		if err != nil || d.Allowed || d.RefusedBy != "guest-total" || d.RetryAfter < time.Second {
			t.Fatalf("admit from an unknown source with the total spent: %+v %v", d, err)
		}
	}
	// A contact's call remembers its source; admit lets it through, for this account alone.
	if d, err := s.Decide(ctx, "acc-1", []Charge{ContactIn("sha256:C", 500)}, "198.51.100.1", now); err != nil || !d.Allowed {
		t.Fatalf("the contact's call: %+v %v", d, err)
	}
	if d, err := s.Admit(ctx, "acc-1", "198.51.100.1", now); err != nil || !d.Allowed {
		t.Fatalf("admit from the contact's source: %+v %v", d, err)
	}
	if d, err := s.Admit(ctx, "acc-2", "198.51.100.1", now); err != nil || !d.Allowed {
		t.Fatalf("another account's total is its own: %+v %v", d, err)
	}
	// An hour on, the source is forgotten (and the total has refilled: a fresh account shows it).
	if d, err := s.Admit(ctx, "acc-1", "198.51.100.1", now.Add(time.Hour+time.Minute)); err != nil || !d.Allowed {
		t.Fatalf("admit an hour later, the total refilled: %+v %v", d, err)
	}
}

func TestASidecarRefusesARulesFileItCannotEnforce(t *testing.T) {
	bad := testRules
	bad.PendingInCap = 0
	dir := t.TempDir()
	config := filepath.Join(dir, "limits.json")
	if err := limitstest.WriteConfig(config, filepath.Join(dir, "l.sock"), bad); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(limitstest.Binary(t), "-config", config).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "pending_in_cap is at least 1") {
		t.Fatalf("a rules file with a cap of 0 started, or did not say why: %v\n%s", err, string(out))
	}
}

func TestTheCardIsTheRulesAndTheCratesAggregate(t *testing.T) {
	s := limitstest.Start(t, testRules)
	ctx := context.Background()
	for _, c := range []struct {
		cap  int
		want float64
	}{{0, 1}, {3, 6}, {500, 7}} {
		a, err := s.Advertise(ctx, c.cap)
		if err != nil {
			t.Fatal(err)
		}
		want := Advertised{ContactCallsPerSecond: 2, ContactBurst: 5, IdentityCallsPerSecond: c.want, GuestCallsPerHour: 3, GuestSourceCallsPerHour: 4}
		if a != want {
			t.Errorf("cap %d: %+v, want %+v", c.cap, a, want)
		}
	}
}

func TestTheShippedConfigurationIsEnforceableAndCarriesTheOwnersNumbers(t *testing.T) {
	r := limitstest.DefaultRules(t)
	// The two numbers the owner set on 2026-09-29 (docs/release/two-layer-limits-2026-09-28.md §6).
	if r.GuestTotalCallsPerHour != 600 || r.PendingInCap != 500 {
		t.Fatalf("deploy/limitd/limits.json: guest total %v, pending cap %v; the owner's are 600 and 500", r.GuestTotalCallsPerHour, r.PendingInCap)
	}
	s := limitstest.StartDefault(t)
	got, err := s.Rules(context.Background())
	if err != nil || got != r {
		t.Fatalf("the sidecar started on the shipped file enforces %+v (%v), the file says %+v", got, err, r)
	}
}

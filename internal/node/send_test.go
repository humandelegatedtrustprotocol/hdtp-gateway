package node

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// AC (P10-07b): the deadline is the sender-chosen `expires`, defaulting to
// PACT §7's 24 hours — not "forever". A message that can never arrive must stop
// being retried and must say so, because an owner is owed the truth.
func TestOutboundExpiryDefaultsToTwentyFourHours(t *testing.T) {
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC).Unix()

	unset := store.Message{CreatedAt: base}
	if got, want := expiryOf(unset), base+24*3600; got != want {
		t.Errorf("default expiry = %d, want %d (created_at + 24h)", got, want)
	}
	chosen := store.Message{CreatedAt: base, ExpiresAt: base + 60}
	if got := expiryOf(chosen); got != base+60 {
		t.Errorf("a sender-chosen expiry was ignored: %d", got)
	}
}

// AC (P10-07b): backoff widens with age, so a peer that has been down for hours
// is not probed every sweep, while a fresh message still retries promptly.
func TestRetryBackoffWidensWithAge(t *testing.T) {
	// Backoff is a function of how many times we have TRIED, not of how old the
	// message is, so the schedule is the same whatever the sweep timing.
	if got := retryDelay(1); got != RetrySweep {
		t.Errorf("first retry delay = %v, want %v", got, RetrySweep)
	}
	if retryDelay(4) <= retryDelay(2) {
		t.Error("the delay does not widen with attempts — that is not backoff")
	}
	if got := retryDelay(40); got != MaxRetryDelay {
		t.Errorf("delay after many attempts = %v, want the %v cap", got, MaxRetryDelay)
	}
}

// AC (P12-03): a pending message is retried on a schedule the node CONTROLS.
//
// The schedule used to be derived from the message's age — `age%1800 < 15` — so
// a retry happened only if a sweep's wall-clock second landed inside a
// 15-second window. Sweeps are not evenly spaced: RetryPending does network I/O
// with timeouts for up to 128 messages, so a sweep takes anywhere from
// milliseconds to minutes, and every window it steps over costs the message
// another half hour. Simulated over six hours: with only ±3s of jitter the worst
// gap was 2 hours against an intended 30 minutes, and on a loaded node it fell
// to ~2 retries in six hours — a message that never leaves before it expires.
//
// This drives the real decision function against jittered sweeps and pins both
// halves: the gap stays bounded, AND the retries stay sparse.
func TestRetriesStayOnScheduleWhenSweepsAreUneven(t *testing.T) {
	const horizon = int64(6 * 3600)
	base := int64(1_700_000_000)

	for _, tc := range []struct {
		name   string
		lo, hi int64
	}{
		{"even 15s sweeps", 15, 15},
		{"mild jitter", 15, 18},
		{"slow sweeps", 15, 90},
		{"loaded node", 60, 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := store.Message{CreatedAt: base}
			var last, worst int64
			var tries int
			var step int64
			for now := base; now < base+horizon; now += step {
				// Deterministic wander across the interval — no Math.random in
				// a test that has to fail the same way twice.
				step = tc.lo + (now/7)%(tc.hi-tc.lo+1)
				if !retryDue(m, now) {
					continue
				}
				tries++
				if last != 0 && now-last > worst {
					worst = now - last
				}
				last = now
				// The peer is still down: record the attempt as the sweeper does.
				m.Attempts++
				m.NextAttemptAt = now + int64(retryDelay(m.Attempts)/time.Second)
			}
			if tries == 0 {
				t.Fatal("a pending message was never retried in six hours")
			}
			if maxGap := int64(MaxRetryDelay/time.Second) + tc.hi; worst > maxGap {
				t.Errorf("worst gap between retries = %d min, want <= %d min",
					worst/60, maxGap/60)
			}
			// The other half: backoff must still hold the rate down.
			if tries > 30 {
				t.Errorf("%d retries in six hours — that is not backoff", tries)
			}
		})
	}
}

// AC (P11-12): a contact cannot point this node's outbound leg at a plaintext
// URL or a private address.
//
// `update_contact` verifies a signature over the new FINGERPRINT, not over the
// card body, and treats an unchanged fingerprint as "an endpoint change" — so an
// active contact can repoint us at will. Over `http` the pinned-key check does
// not merely weaken: it lives in VerifyPeerCertificate, so with no handshake it
// never runs, and the message leaves in cleartext to whatever answered.
func TestContactSuppliedEndpointsAreRefusedWhenUnsafe(t *testing.T) {
	for _, c := range []struct {
		name, endpoint string
		pinned, ok     bool
	}{
		{"ordinary https", "https://peer.example/a/bob/mcp", true, true},
		{"https to a public IP", "https://203.0.113.7:8443/a/bob/mcp", true, true},
		// http never runs the pin, so it is refused however well we know them.
		{"plaintext http, pinned", "http://peer.example/a/bob/mcp", true, false},
		{"plaintext http, unpinned", "http://peer.example/a/bob/mcp", false, false},
		{"http to loopback", "http://127.0.0.1:9000/mcp", true, false},
		// A pinned key makes a private address safe: only its holder can answer,
		// which is what local and same-LAN deployments depend on.
		{"https to loopback, pinned", "https://127.0.0.1:9000/mcp", true, true},
		{"https to RFC1918, pinned", "https://192.168.1.10/mcp", true, true},
		// Unpinned, there is nothing to verify what answered.
		{"https to loopback, unpinned", "https://127.0.0.1:9000/mcp", false, false},
		{"https to RFC1918, unpinned", "https://192.168.1.10/mcp", false, false},
		{"https to metadata, unpinned", "https://169.254.169.254/mcp", false, false},
		{"https to CGNAT, unpinned", "https://100.64.0.1/mcp", false, false},
		{"unparseable", "://nonsense", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := checkEndpoint(c.endpoint, c.pinned)
			if c.ok && err != nil {
				t.Fatalf("a legitimate endpoint was refused: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatalf("%s was accepted", c.endpoint)
			}
		})
	}
}

// The delivery path builds its own reason string, so it needs the same
// treatment: an upstream that refuses with a credential in the message would
// otherwise write it into the trail on every retry.
func TestDeliveryFailureReasonsAreRedacted(t *testing.T) {
	got := whyFailed(errors.New(`dial https://alice:s3cr3tpw@relay.example/mcp: 401 authorization: Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a`))
	for _, secret := range []string{"s3cr3tpw", "ghp_16C7e42F"} {
		if strings.Contains(got, secret) {
			t.Fatalf("a credential reached the audit text: %q", got)
		}
	}
	if !strings.Contains(got, "401") {
		t.Fatalf("the reason was lost: %q", got)
	}
}

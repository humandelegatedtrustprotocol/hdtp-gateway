package public

// Boundary limits (SPEC §5.8, PACT §12): call budgets sized by the contacts an account may hold,
// every one a token bucket, spent BEFORE dispatch; refused calls are audited. Body size is capped
// at the transport so nothing oversized even reaches parsing.
//
// The owner's rule: an account that may hold 500 contacts may be called by all 500 at once, one
// call a second each, so its budget is 500 calls a second and nobody it knows is throttled for
// talking to it. So:
//
//   - per contact, keyed by the account called and the contact's root: 1 call/s, burst 10;
//   - per account, every contact together: the account's contact cap × 1 call/s, burst one
//     second of that, held at NodeCapacityPerSecond, what one node measured it can serve;
//   - per guest, keyed by the account, the proven root and the source address: 10/hour, burst 10;
//   - per source address alone (no root proven — a small form answered chain_required, or a
//     plaintext call with no identity): 60/hour, burst 60, because callers behind one NAT or one
//     provider's egress share an address.
//
// The cloud implements the same buckets with the same numbers (pact-cloud
// gateway/src/identity/limits.ts); a difference between the two is a defect.

import (
	"bytes"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/core"
)

// LimitKind is which budget a call is charged to.
type LimitKind string

const (
	KindContact LimitKind = "contact" // an active contact of the account called
	KindGuest   LimitKind = "guest"   // a proven root that is not one: per root + source
	KindSource  LimitKind = "source"  // nothing proven: the source address alone
)

// LimitKey names who a call is charged to. AccountID is the account the call is ADDRESSED to:
// every budget is that account's, so one account's contacts never spend another's.
type LimitKey struct {
	Kind        LimitKind
	AccountID   string
	Fingerprint string
	IP          string // guests and sources: the source address ("" behind an edge that gave none)
}

// Bucket is a token bucket: it holds at most Burst calls and refills at Rate calls a second.
type Bucket struct {
	Rate  float64
	Burst float64
}

// PACT §12's figures. get_card advertises these same constants (DefaultLimits, LimitsFor).
const (
	ContactCallsPerSecond   = 1
	ContactBurst            = 10
	GuestCallsPerHour       = 10
	GuestSourceCallsPerHour = 60
	// StrangerCallsOutPerHour is what one account may send to addresses it holds no contact
	// for — request_contact, redeem_invite, an acceptance or a refusal — in an hour.
	StrangerCallsOutPerHour = 20
)

// NodeCapacityPerSecond is the most one account's contacts together are let call it in a second,
// whatever its contact cap: what one node was MEASURED to serve, with a margin.
//
// Measured 2026-09-28 by TestMeasureAccountCapacity (internal/node/capacity_test.go) on an Apple
// M2 Max (12 cores), SQLite store: one account, 500 contacts each with its own root and leaf,
// sealing `send_message` over TLS on the real listener, open loop, 5 s steps. Served (every call
// completed, p99 under a second) at up to 280/s in every run; the knee fell between 300/s and
// 450/s from run to run (a cold ramp starting at 350/s held 400/s twice and 450/s once; a ramp from
// 50/s broke at 300/s). `get_card` (the read path) held 400/s and broke at 500/s. At 300/s the
// process was using 1.8 of 12 cores, callers included, so the ceiling is not CPU: what the calls
// wait on was not isolated. The callers run in the same process and pay about what the node does,
// so these figures are a floor for the node alone.
//
// 200 is the lowest knee (280/s) with a margin of about a third. It is below what the default cap
// of 500 contacts asks for (500/s), so a node advertises 200 until a faster store or machine is
// measured. The figure is the node's, and every account on it shares it: the per-account aggregate
// does not divide it between them.
const NodeCapacityPerSecond = 200

var (
	ContactBucket     = Bucket{Rate: ContactCallsPerSecond, Burst: ContactBurst}
	GuestBucket       = Bucket{Rate: GuestCallsPerHour / 3600.0, Burst: GuestCallsPerHour}
	SourceBucket      = Bucket{Rate: GuestSourceCallsPerHour / 3600.0, Burst: GuestSourceCallsPerHour}
	StrangerOutBucket = Bucket{Rate: StrangerCallsOutPerHour / 3600.0, Burst: StrangerCallsOutPerHour}
)

// IdentityCallsPerSecond is one account's aggregate: its contact cap times the per-contact rate,
// held at what the node can serve. The limiter enforces it and get_card advertises it.
func IdentityCallsPerSecond(contactCap int) int {
	if contactCap < 1 {
		contactCap = 1
	}
	return min(contactCap*ContactCallsPerSecond, NodeCapacityPerSecond)
}

// IdentityBucket is the aggregate as a bucket: one second of it is the burst, so every contact
// may call at its own rate at the same moment and none is refused.
func IdentityBucket(contactCap int) Bucket {
	r := float64(IdentityCallsPerSecond(contactCap))
	return Bucket{Rate: r, Burst: r}
}

// Spec is one bucket a call must find a token in.
type Spec struct {
	Key    string
	Bucket Bucket
}

// Specs is every bucket a call keyed by k spends: a contact's own and the account's aggregate; a
// guest's root at its source; a source alone.
func (k LimitKey) Specs(contactCap int) []Spec {
	switch k.Kind {
	case KindContact:
		return []Spec{
			{"contact\x00" + k.AccountID + "\x00" + k.Fingerprint, ContactBucket},
			{"identity\x00" + k.AccountID, IdentityBucket(contactCap)},
		}
	case KindGuest:
		return []Spec{{"guest\x00" + k.AccountID + "\x00" + k.Fingerprint + "\x00" + k.IP, GuestBucket}}
	default:
		return []Spec{{"source\x00" + k.AccountID + "\x00" + k.IP, SourceBucket}}
	}
}

// OutboundSpecs is what one account's call OUT spends: to a contact it holds, that contact's
// bucket and the account's aggregate, the rates it is called at; to anybody else, the account's
// stranger budget.
func OutboundSpecs(accountID, peerRoot string, contact bool, contactCap int) []Spec {
	if contact {
		return []Spec{
			{"out-contact\x00" + accountID + "\x00" + peerRoot, ContactBucket},
			{"out-identity\x00" + accountID, IdentityBucket(contactCap)},
		}
	}
	return []Spec{{"out-stranger\x00" + accountID, StrangerOutBucket}}
}

// limitSweepEvery is how often buckets that have refilled are dropped.
const limitSweepEvery = time.Minute

type bucketState struct {
	tokens float64
	at     time.Time
	b      Bucket
}

// Limiter is a set of token buckets on one clock.
type Limiter struct {
	now func() time.Time
	// ContactCap reports an account's contact cap, which sizes its aggregate. nil means the
	// default (DefaultContactCap).
	ContactCap func(accountID string) int

	mu        sync.Mutex
	state     map[string]*bucketState
	lastSweep time.Time
}

// DefaultContactCap is the contact cap of a node nobody configured.
const DefaultContactCap = core.DefaultLimitContacts

func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, state: map[string]*bucketState{}}
}

func (l *Limiter) contactCap(accountID string) int {
	if l.ContactCap != nil {
		if c := l.ContactCap(accountID); c > 0 {
			return c
		}
	}
	return DefaultContactCap
}

// Allow spends one call of k's budgets, or reports how long until every one of them holds a call
// again (retry_after, PACT §12).
func (l *Limiter) Allow(k LimitKey) (bool, time.Duration) {
	return l.Take(k.Specs(l.contactCap(k.AccountID))...)
}

// AllowOut spends one of accountID's outbound calls to peerRoot (contact: whether accountID holds
// peerRoot as an active contact).
func (l *Limiter) AllowOut(accountID, peerRoot string, contact bool) (bool, time.Duration) {
	return l.Take(OutboundSpecs(accountID, peerRoot, contact, l.contactCap(accountID))...)
}

// Take spends one token from every spec, or from none: a call refused by one bucket costs the
// others nothing. The wait is the longest any refusing bucket needs, in whole seconds, at least 1.
func (l *Limiter) Take(specs ...Spec) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	states := make([]*bucketState, len(specs))
	var wait time.Duration
	for i, sp := range specs {
		st := l.state[sp.Key]
		if st == nil {
			st = &bucketState{tokens: sp.Bucket.Burst, at: now}
		} else {
			st = &bucketState{tokens: refill(st, sp.Bucket, now), at: now}
		}
		st.b = sp.Bucket
		states[i] = st
		if st.tokens < 1 {
			wait = max(wait, RetryAfter(st.tokens, sp.Bucket))
		}
	}
	if wait > 0 {
		return false, wait
	}
	for i, sp := range specs {
		states[i].tokens--
		l.state[sp.Key] = states[i]
	}
	return true, 0
}

// refill is what st holds at now under b: what it held, plus what has dripped in since, never
// more than the burst.
func refill(st *bucketState, b Bucket, now time.Time) float64 {
	elapsed := now.Sub(st.at).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return math.Min(b.Burst, st.tokens+elapsed*b.Rate)
}

// RetryAfter is PACT §12's retry_after for a bucket holding tokens (< 1): the seconds until it
// holds one whole call again, rounded up, at least one.
func RetryAfter(tokens float64, b Bucket) time.Duration {
	secs := math.Ceil((1 - tokens) / b.Rate)
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs) * time.Second
}

// RetryAfterSeconds is a refusal's wait as the integer PACT §12 puts on the wire.
func RetryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

// AuditFn receives boundary events; wired to the audit chain by serve (SPEC
// §11.5). Three fields, like the chain itself: the resource locates what was
// touched, the outcome is the verdict alone.
type AuditFn func(action, resource, outcome string)

// WHERE THE BUDGET IS SPENT. PACT §12 budgets CALLS, and a call is not an HTTP request: an MCP
// client sends `server/discover` or the handshake before it calls, and a limiter at the HTTP layer
// once spent a guest's whole hourly budget before it asked for anything. So the budget is spent in
// the dispatch path (Pool.guarded, and the sealed handler for the inner call), and a refusal is a
// `rate_limited` tool error, which is what a caller's agent can act on.

// CapBody refuses a request body past maxBytes, counted by the bytes that arrive rather than by the
// length the request declares, with 413 and PACT's `too_large` (SPEC §5.7), before anything parses
// it; a body within the cap is handed on whole. It used to wrap the body in a MaxBytesReader and
// leave the answer to whatever read it — which, behind the MCP SDK, was the SDK's own plaintext 413,
// at the SDK's own default of 4 MiB, under this cap: the 8 MiB SPEC §5.7 sizes for 5 MiB of inline
// media was never what the listener took (TestBodyCap held a stub reader, not the listener).
func CapBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxBytes {
			tooLarge(w)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		if err != nil {
			http.Error(w, "the request body could not be read", http.StatusBadRequest)
			return
		}
		if int64(len(b)) > maxBytes {
			tooLarge(w)
			return
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		next.ServeHTTP(w, r)
	})
}

func tooLarge(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_, _ = w.Write([]byte(`{"code":"too_large"}`))
}

// sweepLocked drops buckets that have refilled to their burst: a full bucket is exactly what a
// missing one starts as, so dropping it changes nothing a caller sees. Without it every root and
// every address that ever called would hold an entry for as long as the node ran — and a guest is
// budgeted per root AND address, so cycling either mints a fresh one.
func (l *Limiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < limitSweepEvery {
		return
	}
	l.lastSweep = now
	for k, st := range l.state {
		if refill(st, st.b, now) >= st.b.Burst {
			delete(l.state, k)
		}
	}
}

// Size reports how many buckets the limiter is tracking. Tests use it to prove the map does not
// grow without bound.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.state)
}

// Limits is the boundary metadata get_card advertises (PACT §12): the values
// in force on this node, so a peer can discover an operator-tuned budget
// instead of finding out from too_large or rate_limited. Members are stable
// wire contract — the spec names them.
type Limits struct {
	TextBytes               int `json:"text_bytes"`
	NoteBytes               int `json:"note_bytes"`
	MediaInlineBytes        int `json:"media_inline_bytes"`
	AvailabilitySlots       int `json:"availability_slots"`
	InviteTTLDays           int `json:"invite_ttl_days"`
	ContactCallsPerSecond   int `json:"contact_calls_per_second"`
	ContactBurst            int `json:"contact_burst"`
	IdentityCallsPerSecond  int `json:"identity_calls_per_second"`
	GuestCallsPerHour       int `json:"guest_calls_per_hour"`
	GuestSourceCallsPerHour int `json:"guest_source_calls_per_hour"`
}

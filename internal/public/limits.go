package public

// Boundary limits (SPEC §5.8, PACT §12): per-contact 60 calls/hour, guest tier
// 10/hour per IP+key, enforced BEFORE dispatch; refused calls are audited. Body
// size is capped at the transport so nothing oversized even reaches parsing.

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"
)

type LimitKind string

const (
	KindContact LimitKind = "contact" // 60/hour (PACT §12)
	KindGuest   LimitKind = "guest"   // 10/hour per IP+key (PACT §12)
)

type LimitKey struct {
	Kind        LimitKind
	AccountID   string
	Fingerprint string
	IP          string // guests only: budget is per IP+key
}

func (k LimitKey) mapKey() string {
	return string(k.Kind) + "\x00" + k.AccountID + "\x00" + k.Fingerprint + "\x00" + k.IP
}

func (k LimitKey) budget() int { return DefaultBudget(k.Kind) }

// DefaultBudget is PACT §12's documented per-hour cap for a caller kind — the
// number in force when no operator override is set, and the one the node
// advertises when none is.
func DefaultBudget(kind LimitKind) int {
	if kind == KindGuest {
		return 10
	}
	return 60
}

const limitWindow = time.Hour

// Limiter is a sliding-window counter.
type Limiter struct {
	now func() time.Time
	// Budget reports a key's allowance, letting an operator raise or lower the
	// documented caps while the node runs. nil, or any answer at or below zero,
	// means PACT §12's numbers.
	Budget func(LimitKey) int

	mu        sync.Mutex
	hits      map[string][]time.Time
	lastSweep time.Time
}

func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, hits: map[string][]time.Time{}}
}

// Allow consumes one call if within budget; otherwise reports how long until the
// oldest hit leaves the window (retry_after, PACT §12).
func (l *Limiter) Allow(k LimitKey) (bool, time.Duration) {
	now := l.now()
	cutoff := now.Add(-limitWindow)
	key := k.mapKey()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now, cutoff)
	hits := l.hits[key]
	// prune expired
	i := 0
	for ; i < len(hits); i++ {
		if hits[i].After(cutoff) {
			break
		}
	}
	hits = hits[i:]
	budget := k.budget()
	if l.Budget != nil {
		if b := l.Budget(k); b > 0 {
			budget = b
		}
	}
	if len(hits) >= budget {
		l.hits[key] = hits
		return false, hits[0].Sub(cutoff)
	}
	l.hits[key] = append(hits, now)
	return true, 0
}

// AuditFn receives boundary events; wired to the audit chain by serve (SPEC
// §11.5). Three fields, like the chain itself: the resource locates what was
// touched, the outcome is the verdict alone.
type AuditFn func(action, resource, outcome string)

// LimitMiddleware enforces the rate budget before ANY dispatch work happens.
// NOTE ON PLACEMENT. An earlier version limited at the HTTP layer. That is the
// wrong layer: MCP Streamable HTTP makes several requests per logical call
// (initialize, the POST, an SSE stream), so a single session burned a guest's
// entire hourly budget before it asked for anything. PACT §12 budgets CALLS, so
// the limiter is consumed in the dispatch path — see Pool.guarded — and a
// refusal is a `rate_limited` tool error, which is what a caller's agent can
// actually act on.

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

// sweepLocked drops keys whose window has emptied.
//
// Pruning happens on touch, which only ever reaches keys someone is still
// using. A caller that stops leaves an entry nothing visits again — and the
// keys that stop are exactly the ones an attacker produces in bulk, since a
// guest is budgeted per IP AND key: cycling either dimension mints a fresh
// entry that then sits there. The map grew for as long as the node ran. Once
// per window is enough to bound it, and the cost is one walk an hour.
func (l *Limiter) sweepLocked(now, cutoff time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < limitWindow {
		return
	}
	l.lastSweep = now
	for k, hits := range l.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(l.hits, k)
		}
	}
}

// Size reports how many keys the limiter is tracking. Tests use it to prove the
// map does not grow without bound.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}

// Limits is the boundary metadata get_card advertises (PACT §12): the values
// in force on this node, so a peer can discover an operator-tuned budget
// instead of finding out from too_large or rate_limited. Members are stable
// wire contract — the spec names them.
type Limits struct {
	TextBytes           int `json:"text_bytes"`
	NoteBytes           int `json:"note_bytes"`
	MediaInlineBytes    int `json:"media_inline_bytes"`
	AvailabilitySlots   int `json:"availability_slots"`
	InviteTTLDays       int `json:"invite_ttl_days"`
	ContactCallsPerHour int `json:"contact_calls_per_hour"`
	GuestCallsPerHour   int `json:"guest_calls_per_hour"`
}

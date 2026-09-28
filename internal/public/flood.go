package public

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Flood limits (SPEC §5.7): what the public listener lets in before a request costs the node
// anything — before the TLS handshake for a connection, and before the body is read, the client
// chain is validated or an envelope is opened for a request. They are not PACT §12's call budgets,
// which are per caller and spent at dispatch; these bound the listener as a whole and each source
// address, whatever it claims to be.
//
// The numbers are set from the node's measured capacity. One node served sealed `send_message`
// calls at up to 280/s in every run and broke between 300/s and 450/s (Apple M2 Max, SQLite,
// 2026-09-28: TestMeasureAccountCapacity, node PR #15). The node's own outbound client
// spends two requests per call (`server/discover`, then the call) and opens a connection per call.
// So the node-wide buckets hold twice the highest rate it served, rounded up: more than that is
// refused at the door, where a refusal costs nothing, rather than queued behind work the node
// cannot finish. A source address is held to a quarter of the node, so no one address takes all
// of it. Loopback is never a source address here: it is the node's own tunnel connector or a
// local tool, and the node-wide buckets cover it.
type FloodLimits struct {
	// MaxConns is how many connections may be open at once; one more is closed as it is accepted.
	MaxConns int
	// Conns and IPConns bound new connections: the node's, and each source address's.
	Conns, IPConns Rate
	// Requests and IPRequests bound requests: the node's, and each source address's.
	Requests, IPRequests Rate
}

// Rate is a token bucket: PerSecond sustained, Burst at once.
type Rate struct{ PerSecond, Burst float64 }

// DefaultFloodLimits are the limits every node runs with (see FloodLimits for their measure).
var DefaultFloodLimits = FloodLimits{
	MaxConns:   1024,
	Conns:      Rate{PerSecond: 1000, Burst: 1000},
	IPConns:    Rate{PerSecond: 250, Burst: 250},
	Requests:   Rate{PerSecond: 1000, Burst: 1000},
	IPRequests: Rate{PerSecond: 250, Burst: 250},
}

// Flood is one listener's flood limits, and the count of what they refused.
type Flood struct {
	Limits FloodLimits
	// PerIPConns applies the per-address connection bucket: only on a listener whose socket
	// address IS the caller's (direct mode). Behind a tunnel every connection is the connector's.
	PerIPConns bool
	// SourceIP names a request's source address by the listener's trusted-header rule (SPEC
	// §5.7); the same rule the transport facts use.
	SourceIP func(*http.Request) string
	// Audit receives one row a minute at most, counting what was refused since the last: a flood
	// that wrote a row per refusal would be a flood of the audit chain.
	Audit func(action, resource, outcome string)
	Now   func() time.Time

	buckets  buckets
	open     atomic.Int64
	refused  atomic.Int64
	reported atomic.Int64 // unix nanos of the last audit row
}

func (f *Flood) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// refusedOne counts a refusal, and audits the count once a minute.
func (f *Flood) refusedOne(what string) {
	n := f.refused.Add(1)
	now := f.now().UnixNano()
	last := f.reported.Load()
	if now-last < int64(time.Minute) || !f.reported.CompareAndSwap(last, now) {
		return
	}
	f.refused.Add(-n)
	if f.Audit != nil {
		f.Audit("flood_refused", fmt.Sprintf("last:%s count:%d", what, n), "refused")
	}
}

// Listener wraps the raw listener, beneath TLS: a connection over MaxConns or over a connection
// bucket is closed as it is accepted, before a handshake is begun.
func (f *Flood) Listener(ln net.Listener) net.Listener { return &floodListener{Listener: ln, f: f} }

type floodListener struct {
	net.Listener
	f *Flood
}

func (l *floodListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if why := l.f.admitConn(c.RemoteAddr()); why != "" {
			_ = c.Close()
			l.f.refusedOne(why)
			continue
		}
		return &floodConn{Conn: c, f: l.f}, nil
	}
}

// admitConn says why a new connection is refused, or "" to admit it.
func (f *Flood) admitConn(addr net.Addr) string {
	if f.open.Add(1) > int64(f.Limits.MaxConns) {
		f.open.Add(-1)
		return "connections"
	}
	now := f.now()
	ip := hostOf(addr.String())
	var keys []bucketSpec
	keys = append(keys, bucketSpec{"conns", f.Limits.Conns})
	if f.PerIPConns && !isLoopback(ip) {
		keys = append(keys, bucketSpec{"conns\x00" + ip, f.Limits.IPConns})
	}
	if ok, _ := f.buckets.take(now, keys...); !ok {
		f.open.Add(-1)
		return "connection_rate"
	}
	return ""
}

type floodConn struct {
	net.Conn
	f    *Flood
	once sync.Once
}

func (c *floodConn) Close() error {
	c.once.Do(func() { c.f.open.Add(-1) })
	return c.Conn.Close()
}

// Handler is the outermost handler: a request over a request bucket is answered 429 and
// `rate_limited` before its body is read or its client chain validated.
func (f *Flood) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := []bucketSpec{{"requests", f.Limits.Requests}}
		ip := hostOf(r.RemoteAddr)
		if f.SourceIP != nil {
			ip = f.SourceIP(r)
		}
		if !isLoopback(ip) {
			keys = append(keys, bucketSpec{"requests\x00" + ip, f.Limits.IPRequests})
		}
		if ok, retry := f.buckets.take(f.now(), keys...); !ok {
			f.refusedOne("request_rate")
			secs := strconv.Itoa(int(math.Max(1, math.Ceil(retry.Seconds()))))
			w.Header().Set("Retry-After", secs)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"code":"rate_limited","retry_after":` + secs + `}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func isLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// buckets is a set of token buckets on one clock, swept of full ones once a minute so that a
// flood of source addresses leaves no entries behind.
type buckets struct {
	mu        sync.Mutex
	state     map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
	rate   Rate
}

type bucketSpec struct {
	key  string
	rate Rate
}

func (b *bucket) level(now time.Time) float64 {
	elapsed := now.Sub(b.at).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	return math.Min(b.rate.Burst, b.tokens+elapsed*b.rate.PerSecond)
}

// take spends one token from every spec, or from none, and says how long until all hold one.
func (bs *buckets) take(now time.Time, specs ...bucketSpec) (bool, time.Duration) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.state == nil {
		bs.state = map[string]*bucket{}
	}
	if now.Sub(bs.lastSweep) >= time.Minute {
		bs.lastSweep = now
		for k, b := range bs.state {
			if b.level(now) >= b.rate.Burst {
				delete(bs.state, k)
			}
		}
	}
	levels := make([]float64, len(specs))
	var wait time.Duration
	for i, sp := range specs {
		lv := sp.rate.Burst
		if b := bs.state[sp.key]; b != nil {
			lv = b.level(now)
		}
		levels[i] = lv
		if lv < 1 {
			wait = max(wait, time.Duration((1-lv)/sp.rate.PerSecond*float64(time.Second)))
		}
	}
	if wait > 0 {
		return false, wait
	}
	for i, sp := range specs {
		bs.state[sp.key] = &bucket{tokens: levels[i] - 1, at: now, rate: sp.rate}
	}
	return true, 0
}

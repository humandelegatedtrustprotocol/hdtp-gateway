package public

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnCap bounds how many connections the public listener holds open at once (SPEC §5.7): past
// Max, a connection is closed as it is accepted, beneath TLS, before a handshake is begun. It is
// server hygiene, beside the timeouts on the node's http.Server and the body cap. Rate limits —
// per source address, or for the whole node — are not the node's: they belong to what stands in
// front of it (the owner's decision of 2026-09-28).
type ConnCap struct {
	Max int
	// Audit receives one row a minute at most, counting the connections refused since the last:
	// a row per refusal would turn a flood of connections into a flood of the audit chain.
	Audit func(action, resource, outcome string)
	Now   func() time.Time

	open     atomic.Int64
	refused  atomic.Int64
	reported atomic.Int64 // unix nanos of the last audit row
}

// DefaultMaxConns is the cap every node runs with: far above what one node serves at once (it was
// measured serving a few hundred sealed calls a second, each a short request), and a bound on what
// a flood of idle connections can hold.
const DefaultMaxConns = 1024

func (c *ConnCap) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Listener wraps the raw listener, beneath TLS.
func (c *ConnCap) Listener(ln net.Listener) net.Listener { return &capListener{Listener: ln, c: c} }

type capListener struct {
	net.Listener
	c *ConnCap
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.c.open.Add(1) > int64(l.c.Max) {
			l.c.open.Add(-1)
			_ = conn.Close()
			l.c.refusedOne()
			continue
		}
		return &capConn{Conn: conn, c: l.c}, nil
	}
}

// refusedOne counts a refusal, and audits the count once a minute.
func (c *ConnCap) refusedOne() {
	n := c.refused.Add(1)
	now := c.now().UnixNano()
	last := c.reported.Load()
	if now-last < int64(time.Minute) || !c.reported.CompareAndSwap(last, now) {
		return
	}
	c.refused.Add(-n)
	if c.Audit != nil {
		c.Audit("listener_full", fmt.Sprintf("max:%d count:%d", c.Max, n), "refused")
	}
}

type capConn struct {
	net.Conn
	c    *ConnCap
	once sync.Once
}

func (cc *capConn) Close() error {
	cc.once.Do(func() { cc.c.open.Add(-1) })
	return cc.Conn.Close()
}

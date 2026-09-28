package public

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeListener hands out in-memory connections with the source addresses a test names.
type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type addrConn struct {
	net.Conn
	remote fakeAddr
	closed *atomic.Bool
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }
func (c addrConn) Close() error         { c.closed.Store(true); return c.Conn.Close() }

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, errors.New("closed")
	}
}
func (l *fakeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *fakeListener) Addr() net.Addr { return fakeAddr("127.0.0.1:1") }

// A connection past Max is closed as it is accepted — beneath TLS, before a handshake could
// begin — and audited as one row a minute counting the refusals; once a connection closes, the
// next is admitted: a cap that refused everything would pass the first half alone.
func TestTheListenerClosesAConnectionPastItsCapAndAdmitsTheNext(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var rows []string
	var mu sync.Mutex
	fl := &fakeListener{conns: make(chan net.Conn, 64), closed: make(chan struct{})}
	c := &ConnCap{Max: 2, Now: func() time.Time { return now },
		Audit: func(a, r, o string) { mu.Lock(); rows = append(rows, a+" "+r+" "+o); mu.Unlock() }}
	ln := c.Listener(fl)
	defer ln.Close()
	dial := func() *atomic.Bool {
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close() })
		closed := &atomic.Bool{}
		fl.conns <- addrConn{Conn: server, remote: fakeAddr("203.0.113.9:5000"), closed: closed}
		return closed
	}
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	take := func(what string) net.Conn {
		t.Helper()
		select {
		case conn := <-accepted:
			return conn
		case <-time.After(5 * time.Second):
			t.Fatalf("%s was not accepted", what)
			return nil
		}
	}
	waitClosed := func(b *atomic.Bool, what string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !b.Load() && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		if !b.Load() {
			t.Fatalf("%s was not closed", what)
		}
	}

	first := dial()
	c1 := take("the first connection")
	dial()
	take("the second connection")
	for i := 0; i < 5; i++ {
		waitClosed(dial(), "a connection past the cap")
	}
	if first.Load() {
		t.Fatal("an admitted connection was closed")
	}
	mu.Lock()
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "listener_full max:2 count:1 ") {
		t.Fatalf("five refusals wrote %v, want the first alone within the minute", rows)
	}
	mu.Unlock()

	// The control: a slot frees, the next connection gets through.
	c1.Close()
	dial()
	take("a connection after one closed")
}

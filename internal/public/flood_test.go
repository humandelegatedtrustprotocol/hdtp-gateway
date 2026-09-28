package public

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// untouchable is a body that fails the test if anything reads it.
type untouchable struct{ t *testing.T }

func (u untouchable) Read([]byte) (int, error) {
	u.t.Error("a refused request's body was read")
	return 0, io.EOF
}

// A flood from one source address is refused at the request bucket — 429, `rate_limited`, a
// Retry-After — before anything reads its body or runs the handler behind it, and a request from
// another address, sent last, still gets through: a limit that refused everybody would pass the
// first half alone. A flood of many addresses meets the node-wide bucket.
func TestAFloodFromOneAddressIsRefusedBeforeItsBodyAndAnotherGetsThrough(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var served atomic.Int64
	var rows []string
	f := &Flood{
		Limits: FloodLimits{MaxConns: 10, Conns: Rate{100, 100}, IPConns: Rate{100, 100},
			Requests: Rate{1, 20}, IPRequests: Rate{1, 5}},
		Now:   func() time.Time { return now },
		Audit: func(a, r, o string) { rows = append(rows, a+" "+r+" "+o) },
	}
	h := f.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	send := func(ip string, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/a/x/mcp", body)
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 5; i++ {
		if rec := send("203.0.113.9", strings.NewReader("{}")); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the address's burst: %d", i, rec.Code)
		}
	}
	for i := 0; i < 50; i++ {
		rec := send("203.0.113.9", untouchable{t})
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" ||
			rec.Body.String() != `{"code":"rate_limited","retry_after":1}` {
			t.Fatalf("flood request %d: %d %q %s", i, rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
		}
	}
	if n := served.Load(); n != 5 {
		t.Fatalf("the handler ran %d times for 5 admitted requests and 50 refused", n)
	}
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "flood_refused last:request_rate count:1 ") {
		t.Fatalf("a flood of 50 refusals wrote %d audit rows (%v), want the first alone within the minute", len(rows), rows)
	}
	// The control: another address, after the flood.
	if rec := send("198.51.100.7", strings.NewReader("{}")); rec.Code != http.StatusOK {
		t.Fatalf("an address that sent nothing was refused after another's flood: %d", rec.Code)
	}

	// Many addresses, one request each: the node-wide bucket (burst 20; 6 spent above).
	refused := 0
	for i := 0; i < 30; i++ {
		ip := net.IPv4(192, 0, 2, byte(i+1)).String()
		if send(ip, strings.NewReader("{}")).Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused != 16 {
		t.Fatalf("30 addresses against a node-wide burst with 14 left: %d refused, want 16", refused)
	}
	// It refills: a minute on, the rows say how many were refused meanwhile.
	now = now.Add(time.Minute)
	if rec := send("198.51.100.7", strings.NewReader("{}")); rec.Code != http.StatusOK {
		t.Fatalf("after the node-wide bucket refilled: %d", rec.Code)
	}
	for i := 0; i < 10; i++ {
		send("203.0.113.9", strings.NewReader("{}"))
	}
	if len(rows) != 2 || !strings.HasPrefix(rows[1], "flood_refused last:request_rate count:66 ") {
		t.Fatalf("rows after a minute: %v", rows)
	}
}

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

// Connections are refused as they are accepted — closed before a TLS handshake could begin — once
// one address has spent its connection bucket, and once MaxConns are open; a connection from
// another address, and one after a slot frees, still get through.
func TestConnectionsAreRefusedBeneathTLSAndAnotherAddressGetsThrough(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fl := &fakeListener{conns: make(chan net.Conn, 64), closed: make(chan struct{})}
	f := &Flood{
		Limits: FloodLimits{MaxConns: 4, Conns: Rate{100, 100}, IPConns: Rate{1, 2},
			Requests: Rate{100, 100}, IPRequests: Rate{100, 100}},
		PerIPConns: true, Now: func() time.Time { return now },
	}
	ln := f.Listener(fl)
	defer ln.Close()
	dial := func(ip string) *atomic.Bool {
		server, client := net.Pipe()
		t.Cleanup(func() { client.Close() })
		closed := &atomic.Bool{}
		fl.conns <- addrConn{Conn: server, remote: fakeAddr(ip + ":5000"), closed: closed}
		return closed
	}
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	take := func(what string) net.Conn {
		t.Helper()
		select {
		case c := <-accepted:
			return c
		case <-time.After(5 * time.Second):
			t.Fatalf("%s was not accepted", what)
			return nil
		}
	}

	a1, a2 := dial("203.0.113.9"), dial("203.0.113.9")
	c1, c2 := take("the first of an address's burst"), take("the second of an address's burst")
	refusedA := dial("203.0.113.9")
	control := dial("198.51.100.7")
	c3 := take("another address's connection, after the first spent its burst")
	if refusedA.Load() == false {
		t.Fatal("a connection past its address's burst was not closed")
	}
	if a1.Load() || a2.Load() || control.Load() {
		t.Fatal("an admitted connection was closed")
	}

	// MaxConns: three open; a fourth from a fresh address fits, a fifth does not.
	dial("192.0.2.1")
	c4 := take("the fourth connection")
	overCap := dial("192.0.2.2")
	for deadline := time.Now().Add(5 * time.Second); !overCap.Load() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !overCap.Load() {
		t.Fatal("a connection past MaxConns was not closed")
	}
	// A slot frees: the next gets through.
	c1.Close()
	dial("192.0.2.3")
	take("a connection after one closed")
	for _, c := range []net.Conn{c2, c3, c4} {
		c.Close()
	}
}

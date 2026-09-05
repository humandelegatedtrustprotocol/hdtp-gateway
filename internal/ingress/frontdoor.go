package ingress

// One public port for both ingress modes (SPEC §10.6).
//
// Passthrough routes raw TLS by SNI and terminate answers TLS itself, and both
// want 443. The ingress could only do one at a time: `vhost-port` defaulted to
// 443 and `terminate-bind` had to be some other port, so a terminate-mode node
// was reachable at `https://name.example:8443` — which is not "just a domain",
// and is not a URL a peer's card can usefully carry.
//
// The front door reads only the ClientHello, decides from the SNI which mode the
// subdomain was paired in, and hands the connection on with those bytes intact.
// It never terminates TLS itself: a passthrough connection stays end-to-end
// encrypted to the node, which is the entire point of that mode.

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// helloTimeout bounds how long a connection may take to say what it wants. A
// peer that opens a socket and sends nothing must not hold a slot.
const helloTimeout = 10 * time.Second

// handoffTimeout bounds waiting for the terminator to take a connection. It
// accepts in a tight loop, so anything approaching this means it is not running.
const handoffTimeout = 5 * time.Second

// ConnSink receives connections routed to it, and may refuse.
type ConnSink interface {
	// Deliver hands over one connection, reporting whether it was taken. It
	// MUST NOT block indefinitely: the caller is holding a public connection.
	Deliver(c net.Conn, timeout time.Duration) bool
}

// FrontDoor accepts on the public port and routes by SNI.
type FrontDoor struct {
	Registry Registry
	Domain   string
	// Terminate receives connections for terminate-mode subdomains. It is a
	// sink rather than a bare channel because handing over must be able to GIVE
	// UP: a plain blocking send on an unbuffered channel parks a goroutine and
	// a socket forever the moment the terminator stops accepting, and the
	// connections arrive from the public internet — so that is an unbounded
	// remote-driven leak, not a rare edge.
	Terminate ConnSink
	// PassthroughAddr is the SNI-routing data plane (the frps vhost port).
	PassthroughAddr string
	Audit           func(action, resource, outcome string)
	DialTimeout     time.Duration

	mu sync.Mutex
	ln net.Listener
}

func (f *FrontDoor) audit(action, resource, outcome string) {
	if f.Audit != nil {
		f.Audit(action, resource, outcome)
	}
}

// Serve accepts until the listener closes.
func (f *FrontDoor) Serve(ln net.Listener) error {
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go f.route(c)
	}
}

func (f *FrontDoor) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		return f.ln.Close()
	}
	return nil
}

func (f *FrontDoor) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	peeked, sni, err := peekSNI(c)
	if err != nil {
		f.audit("ingress_route", "sni:unknown", "bad_hello")
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	conn := &replayConn{Conn: c, replay: peeked}

	sub, ok := subdomainOf(sni, f.Domain)
	if !ok {
		f.audit("ingress_route", "sni:"+sni, "not_our_domain")
		conn.Close()
		return
	}
	n, ok := f.Registry.BySubdomain(sub)
	if !ok {
		// An unpaired name must not reveal whether it exists: dropping is the
		// same answer a closed port gives.
		f.audit("ingress_route", "subdomain:"+sub, "unpaired")
		conn.Close()
		return
	}
	if n.Mode == ModeTerminate {
		if f.Terminate == nil {
			f.audit("ingress_route", "subdomain:"+sub, "terminate_not_configured")
			conn.Close()
			return
		}
		if !f.Terminate.Deliver(conn, handoffTimeout) {
			// The terminator is gone or wedged. Dropping is the same answer a
			// closed port gives, and it is the only one that does not leak.
			f.audit("ingress_route", "subdomain:"+sub, "terminate_unavailable")
			conn.Close()
			return
		}
		f.audit("ingress_route", "subdomain:"+sub, "terminate")
		return
	}
	f.audit("ingress_route", "subdomain:"+sub, "passthrough")
	f.splice(conn)
}

// splice forwards raw bytes to the data plane. The connection is NOT decrypted
// here: passthrough exists precisely so the ingress cannot read it (§10.6).
func (f *FrontDoor) splice(c net.Conn) {
	defer c.Close()
	timeout := f.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	up, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", f.PassthroughAddr)
	if err != nil {
		f.audit("ingress_route", "data_plane:"+f.PassthroughAddr, "unreachable")
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// subdomainOf maps an SNI back to a registry subdomain.
func subdomainOf(sni, domain string) (string, bool) {
	suffix := "." + domain
	if len(sni) <= len(suffix) || sni[len(sni)-len(suffix):] != suffix {
		return "", false
	}
	return sni[:len(sni)-len(suffix)], true
}

// ChanListener turns a channel of connections into a net.Listener, so the
// Terminator can go on consuming a listener while the front door decides which
// connections belong to it.
type ChanListener struct {
	C      chan net.Conn
	Addr_  net.Addr
	closed chan struct{}
	once   sync.Once
}

func NewChanListener(addr net.Addr) *ChanListener {
	return &ChanListener{C: make(chan net.Conn), Addr_: addr, closed: make(chan struct{})}
}

// Deliver hands a connection to whoever is accepting, giving up if the listener
// has closed or nobody takes it in time.
func (l *ChanListener) Deliver(c net.Conn, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case l.C <- c:
		return true
	case <-l.closed:
		return false
	case <-t.C:
		return false
	}
}

func (l *ChanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.C:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *ChanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *ChanListener) Addr() net.Addr { return l.Addr_ }

/* ----------------------------- ClientHello ----------------------------- */

// replayConn hands back the bytes peekSNI consumed, so the next reader sees an
// untouched stream.
type replayConn struct {
	net.Conn
	replay []byte
	off    int
}

func (r *replayConn) Read(p []byte) (int, error) {
	if r.off < len(r.replay) {
		n := copy(p, r.replay[r.off:])
		r.off += n
		return n, nil
	}
	return r.Conn.Read(p)
}

var errNotTLS = errors.New("ingress: not a TLS ClientHello")

// peekSNI reads exactly one TLS record, extracts the server name, and returns
// every byte it consumed so the caller can replay them.
func peekSNI(c net.Conn) ([]byte, string, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, "", err
	}
	if hdr[0] != 0x16 { // handshake
		return hdr, "", errNotTLS
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length <= 0 || length > 16384 {
		return hdr, "", errNotTLS
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c, body); err != nil {
		return hdr, "", err
	}
	raw := append(hdr, body...)
	sni, err := sniFromClientHello(body)
	return raw, sni, err
}

// sniFromClientHello walks a ClientHello to its server_name extension. It reads
// only what it must and refuses anything malformed rather than guessing.
func sniFromClientHello(b []byte) (string, error) {
	// handshake header: type(1) length(3)
	if len(b) < 4 || b[0] != 0x01 {
		return "", errNotTLS
	}
	p := b[4:]
	if len(p) < 34 { // version(2) random(32)
		return "", errNotTLS
	}
	p = p[34:]
	if len(p) < 1 { // session id
		return "", errNotTLS
	}
	sidLen := int(p[0])
	if len(p) < 1+sidLen {
		return "", errNotTLS
	}
	p = p[1+sidLen:]
	if len(p) < 2 { // cipher suites
		return "", errNotTLS
	}
	csLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+csLen {
		return "", errNotTLS
	}
	p = p[2+csLen:]
	if len(p) < 1 { // compression
		return "", errNotTLS
	}
	compLen := int(p[0])
	if len(p) < 1+compLen {
		return "", errNotTLS
	}
	p = p[1+compLen:]
	if len(p) < 2 { // extensions
		return "", errNotTLS
	}
	extTotal := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extTotal {
		return "", errNotTLS
	}
	p = p[:extTotal]
	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		if len(p) < 4+l {
			return "", errNotTLS
		}
		if typ == 0 { // server_name
			e := p[4 : 4+l]
			if len(e) < 5 {
				return "", errNotTLS
			}
			// list length(2) type(1) name length(2)
			nameLen := int(e[3])<<8 | int(e[4])
			if len(e) < 5+nameLen {
				return "", errNotTLS
			}
			return string(e[5 : 5+nameLen]), nil
		}
		p = p[4+l:]
	}
	return "", errNotTLS // no SNI: nothing to route on
}

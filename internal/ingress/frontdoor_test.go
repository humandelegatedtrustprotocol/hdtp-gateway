package ingress

import (
	"crypto/tls"
	"net"
	"runtime"
	"testing"
	"time"
)

// AC (P10-06d): one public port serves both modes.
//
// Passthrough routes raw TLS by SNI and terminate answers TLS itself, and both
// wanted 443 — so the ingress could only do one, and a terminate-mode node was
// reachable at `https://name.example:8443`. That is not "just a domain", and not
// a URL a peer's card can usefully carry.
func TestOnePortRoutesPassthroughAndTerminateBySNI(t *testing.T) {
	reg := NewMemoryRegistry(nil)
	if err := reg.Put(Node{Fingerprint: "sha256:p", Subdomain: "pass", Mode: ModePassthrough}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(Node{Fingerprint: "sha256:t", Subdomain: "term", Mode: ModeTerminate}); err != nil {
		t.Fatal(err)
	}

	// A stand-in data plane: whatever reaches it is passthrough traffic, and it
	// must arrive with the ClientHello intact.
	dp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dp.Close()
	spliced := make(chan []byte, 1)
	go func() {
		c, err := dp.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		spliced <- buf[:n]
	}()

	termLn := NewChanListener(dp.Addr())
	defer termLn.Close()
	terminated := make(chan string, 1)
	go func() {
		for {
			c, err := termLn.Accept()
			if err != nil {
				return
			}
			// The bytes must be replayable: a TLS server on top has to see the
			// ClientHello the front door already read, whole.
			_, sni, err := peekSNI(c)
			if err != nil {
				terminated <- "ERR:" + err.Error()
			} else {
				terminated <- sni
			}
			c.Close()
		}
	}()

	fd := &FrontDoor{
		Registry: reg, Domain: "example.test",
		Terminate: termLn, PassthroughAddr: dp.Addr().String(),
	}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = fd.Serve(front) }()
	defer fd.Close()

	dial := func(sni string) {
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// A real ClientHello, so the SNI parser is exercised, not a fixture.
		tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
		_ = tc.Handshake() // fails: nothing completes it. The routing already happened.
	}

	dial("term.example.test")
	select {
	case got := <-terminated:
		if got != "term.example.test" {
			t.Fatalf("terminate side saw SNI %q — the ClientHello was not replayed intact", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a terminate subdomain never reached the terminator")
	}

	dial("pass.example.test")
	select {
	case b := <-spliced:
		if len(b) < 5 || b[0] != 0x16 {
			t.Fatalf("the data plane did not receive a raw ClientHello: % x", b)
		}
		if sni, err := sniFromClientHello(b[5:]); err != nil || sni != "pass.example.test" {
			t.Fatalf("passthrough bytes were altered in transit (sni %q err %v)", sni, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a passthrough subdomain never reached the data plane")
	}

	// An unpaired name is dropped, and says nothing about whether it exists.
	c, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "nobody.example.test", InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("an unpaired subdomain was served")
	}
	c.Close()
}

// AC: a stream that is not a ClientHello is refused rather than guessed at.
func TestFrontDoorRefusesNonTLS(t *testing.T) {
	if _, _, err := peekSNI(pipeWith([]byte("GET / HTTP/1.1\r\n\r\n"))); err == nil {
		t.Fatal("plain HTTP was accepted as a ClientHello")
	}
}

func pipeWith(b []byte) net.Conn {
	client, server := net.Pipe()
	go func() { _, _ = server.Write(b); _ = server.Close() }()
	return client
}

// AC: the front door must not park a goroutine and a public socket when the
// terminator is not taking connections.
//
// The handoff was a plain blocking send on an unbuffered channel. If the
// terminator stopped accepting — closed, wedged, or never started — every
// subsequent terminate connection blocked forever holding a socket. Those
// connections arrive from the public internet, so that is an unbounded
// remote-driven leak, not a rare edge.
func TestFrontDoorDropsWhenTheTerminatorIsNotAccepting(t *testing.T) {
	reg := NewMemoryRegistry(nil)
	if err := reg.Put(Node{Fingerprint: "sha256:t", Subdomain: "term", Mode: ModeTerminate}); err != nil {
		t.Fatal(err)
	}
	// A listener nobody ever accepts from, then closed.
	termLn := NewChanListener(&net.TCPAddr{})
	termLn.Close()

	fd := &FrontDoor{Registry: reg, Domain: "example.test", Terminate: termLn}
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = fd.Serve(front) }()
	defer fd.Close()

	before := runtime.NumGoroutine()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{ServerName: "term.example.test", InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tc.Handshake()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was never released — the handoff still blocks")
	}

	// Give the router a moment, then confirm it is not accumulating.
	time.Sleep(200 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+8 {
		t.Fatalf("goroutines grew from %d to %d handling one dropped connection", before, after)
	}

	// And a closed listener must report the refusal rather than block.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	start := time.Now()
	if termLn.Deliver(c1, 2*time.Second) {
		t.Fatal("a closed listener accepted a connection")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a closed listener took %v to refuse — it waited out the timeout", elapsed)
	}
}

// AC (P11-15): the data plane's vhost is an INTERNAL hop and must not be
// reachable from outside.
//
// frp defaults ProxyBindAddr to BindAddr, and BindAddr is 0.0.0.0 because nodes
// must be able to dial the control port from anywhere. Once the front door
// became the public entrance, that left the vhost listening on every interface
// too — so a caller could connect straight to it and skip the registry lookup,
// the unpaired-name drop and the passthrough/terminate decision entirely,
// including reaching a terminate-mode node by its internal name.
func TestDataPlaneVhostDefaultsToLoopback(t *testing.T) {
	d := &DataPlane{BindAddr: "0.0.0.0", BindPort: 7000, VhostHTTPSPort: 7443}
	if got := d.proxyBindAddr(); got != "127.0.0.1" {
		t.Fatalf("the vhost binds %q — outside callers can bypass the front door", got)
	}
	// An operator who genuinely wants it elsewhere can still say so.
	d.ProxyBindAddr = "10.0.0.5"
	if got := d.proxyBindAddr(); got != "10.0.0.5" {
		t.Fatalf("an explicit bind address was ignored: %q", got)
	}
}

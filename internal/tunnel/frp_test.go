package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
)

func TestFRPOptionsPlumbing(t *testing.T) {
	if _, err := frpOptions(Options{PublicBind: "127.0.0.1:8443"}); err == nil || !strings.Contains(err.Error(), "server_addr") {
		t.Fatalf("server_addr not required: %v", err)
	}
	if _, err := frpOptions(Options{PublicBind: "127.0.0.1:8443", Extra: map[string]string{"server_addr": "vps"}}); err == nil || !strings.Contains(err.Error(), "remote_port") {
		t.Fatalf("tcp remote_port not required: %v", err)
	}
	if _, err := frpOptions(Options{PublicBind: "127.0.0.1:8443", Extra: map[string]string{"server_addr": "vps", "proxy_type": "https"}}); err == nil || !strings.Contains(err.Error(), "custom_domain") {
		t.Fatalf("https custom_domain not required: %v", err)
	}
	if _, err := frpOptions(Options{PublicBind: "127.0.0.1:8443", Extra: map[string]string{"server_addr": "vps", "proxy_type": "udp", "remote_port": "1"}}); err == nil {
		t.Fatal("bad proxy_type accepted")
	}
	f, err := frpOptions(Options{PublicBind: "0.0.0.0:8443", Extra: map[string]string{"server_addr": "vps.example", "remote_port": "9443", "token": "t"}})
	if err != nil || f.ServerPort != 7000 || f.LocalIP != "127.0.0.1" || f.LocalPort != 8443 || f.publicURL() != "https://vps.example:9443" {
		t.Fatalf("%+v %v", f, err)
	}
	h, _ := frpOptions(Options{PublicBind: "127.0.0.1:8443", Extra: map[string]string{"server_addr": "vps", "proxy_type": "https", "custom_domain": "hdtp.example", "vhost_https_port": "8443"}})
	if h.publicURL() != "https://hdtp.example:8443" {
		t.Fatalf("https url: %s", h.publicURL())
	}
	if edge, err := derivesEdge(t, "frp"); err != nil || edge {
		t.Fatal("frp must be direct mode")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// AC: mTLS end to end THROUGH the tunnel — an embedded frps (the real server
// library, in-process) fronts the node's own TLS listener; a caller's client
// certificate is visible to the node on the far side.
func TestFRPPassthroughKeepsClientCertVisible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// embedded frps
	bindPort := freePort(t)
	scfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: bindPort}
	scfg.Auth.Method = v1.AuthMethodToken
	scfg.Auth.Token = "s3cret"
	if err := scfg.Complete(); err != nil {
		t.Fatal(err)
	}
	frps, err := server.NewService(scfg)
	if err != nil {
		t.Fatal(err)
	}
	go frps.Run(ctx)
	defer frps.Close()

	// the "node": its own TLS listener requesting client certs, echoing the
	// caller's SPKI fingerprint
	nodeKP, _ := identity.Generate(identity.AlgoP256)
	nodeDER, _ := identity.SelfSignedCert(nodeKP, "node")
	nodePort := freePort(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:"+strconv.Itoa(nodePort), &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{nodeDER}, PrivateKey: nodeKP.Signer}},
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					return
				}
				seen := "none"
				if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
					seen, _ = identity.Fingerprint(certs[0].PublicKey)
				}
				fmt.Fprintf(tc, "peer=%s\n", seen)
			}(c)
		}
	}()

	// the adapter: tcp proxy remote port → node's bind
	remotePort := freePort(t)
	a, err := New("frp", Options{PublicBind: "127.0.0.1:" + strconv.Itoa(nodePort), Extra: map[string]string{
		"server_addr": "127.0.0.1", "server_port": strconv.Itoa(bindPort), "token": "s3cret",
		"remote_port": strconv.Itoa(remotePort),
	}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	if info.TerminatesAtEdge || info.Listener != nil || info.PublicURL != "https://127.0.0.1:"+strconv.Itoa(remotePort) {
		t.Fatalf("info: %+v", info)
	}

	// a caller with its own identity cert dials the PUBLIC (frps) port
	callerKP, _ := identity.Generate(identity.AlgoEd25519)
	callerDER, _ := identity.SelfSignedCert(callerKP, "caller")
	var line string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(remotePort), &tls.Config{
			InsecureSkipVerify: true, // the test pins nothing; it asserts the CLIENT cert path
			Certificates:       []tls.Certificate{{Certificate: [][]byte{callerDER}, PrivateKey: callerKP.Signer}},
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			time.Sleep(200 * time.Millisecond) // frpc is still registering the proxy
			continue
		}
		// the server cert that arrived is the NODE's own — frps did not terminate
		if got := conn.ConnectionState().PeerCertificates; len(got) == 0 || !x509CertMatches(got[0], nodeDER) {
			t.Fatal("served certificate is not the node's: something terminated TLS in between")
		}
		b, _ := io.ReadAll(conn)
		conn.Close()
		line = strings.TrimSpace(string(b))
		break
	}
	if line != "peer="+callerKP.Fingerprint {
		t.Fatalf("node saw %q, want the caller's client cert %s", line, callerKP.Fingerprint)
	}
	if st := a.Status(); !st.Running || st.Name != "frp" {
		t.Fatalf("status: %+v", st)
	}
}

func x509CertMatches(c *x509.Certificate, der []byte) bool {
	return string(c.Raw) == string(der)
}

// AC: a caller who reaches the public port while the frp client is still
// registering its proxy is a normal caller. frps opens the remote port and hands
// out work connections before the client has finished recording the proxy as
// running, so the client's work-connection path and its registration path run
// at once; under -race this test fails if they touch the proxy's state without
// the proxy's lock (frp v0.71.0 read the phase unlocked), and its Stop fails it
// if the client's shutdown reads the control without its lock (frp v0.71.0 did):
// third_party/frp.patch.
func TestFRPCallersDuringRegistrationAreServed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bindPort := freePort(t)
	scfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: bindPort}
	scfg.Auth.Method = v1.AuthMethodToken
	scfg.Auth.Token = "s3cret"
	if err := scfg.Complete(); err != nil {
		t.Fatal(err)
	}
	frps, err := server.NewService(scfg)
	if err != nil {
		t.Fatal(err)
	}
	go frps.Run(ctx)
	defer frps.Close()

	// the node's bind: answers every connection with one line
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "node\n")
			_ = c.Close()
		}
	}()

	remotePort := freePort(t)
	a, err := New("frp", Options{PublicBind: ln.Addr().String(), Extra: map[string]string{
		"server_addr": "127.0.0.1", "server_port": strconv.Itoa(bindPort), "token": "s3cret",
		"remote_port": strconv.Itoa(remotePort),
	}})
	if err != nil {
		t.Fatal(err)
	}
	// the callers are already dialling when Start is called, so the first of
	// them arrive in the instant frps opens the port
	const callers = 32
	answers := make(chan string, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(remotePort), time.Second)
				if err != nil {
					continue // the port is not open yet
				}
				b, _ := io.ReadAll(c)
				_ = c.Close()
				if string(b) == "node\n" {
					answers <- "node"
					return
				}
				// frp dropped a caller that came in during registration: dial again
			}
			answers <- "timed out"
		}()
	}
	close(start)
	if _, err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	for range callers {
		if got := <-answers; got != "node" {
			t.Fatalf("a caller was never served: %s", got)
		}
	}
}

// AC: the adapter can be stopped the moment it is started — serve does exactly
// that when the node fails to start after the tunnel came up. frp v0.71.0's
// GracefulClose called the cancel func Run sets on its own goroutine: a data
// race, and a nil call (a panic) when Run had not set it yet
// (third_party/frp.patch). Nothing listens on the frps port; Stop must still
// return, and return Run's goroutine with it.
func TestFRPStopRightAfterStart(t *testing.T) {
	a, err := New("frp", Options{PublicBind: "127.0.0.1:1", Extra: map[string]string{
		"server_addr": "127.0.0.1", "server_port": strconv.Itoa(freePort(t)), "remote_port": "2",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := a.(*FRP)
	done := f.runDone
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Stop returned with frp's Run still running")
	}
}

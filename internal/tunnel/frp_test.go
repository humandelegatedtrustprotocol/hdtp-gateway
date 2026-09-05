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

	"github.com/tech-sumit/pact-gateway/internal/identity"
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
	h, _ := frpOptions(Options{PublicBind: "127.0.0.1:8443", Extra: map[string]string{"server_addr": "vps", "proxy_type": "https", "custom_domain": "pact.example", "vhost_https_port": "8443"}})
	if h.publicURL() != "https://pact.example:8443" {
		t.Fatalf("https url: %s", h.publicURL())
	}
	if edge, err := TerminatesAtEdge("frp"); err != nil || edge {
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
	if raceEnabled {
		// Upstream frp v0.71.0 races its own shutdown (client.Service.stop vs
		// keepControllerWorking) — a library bug, not ours. The mTLS assertions
		// below still run under -race; only the teardown is left to process exit.
		t.Log("frp Stop skipped under -race: upstream shutdown race in frp client")
	} else {
		defer a.Stop()
	}
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

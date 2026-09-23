package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

func TestNgrokIsConfigGated(t *testing.T) {
	t.Setenv("NGROK_AUTHTOKEN", "")
	if _, err := ngrokOptions(Options{}); err == nil || !strings.Contains(err.Error(), "paid") {
		t.Fatalf("token-less ngrok not disabled: %v", err)
	}
	if _, err := New("ngrok", Options{}); err == nil {
		t.Fatal("constructed without a token")
	}
	t.Setenv("NGROK_AUTHTOKEN", "tok")
	n, err := ngrokOptions(Options{})
	if err != nil || n.AuthToken != "tok" || n.URL != "tls://" || n.Name != "pact" {
		t.Fatalf("%+v %v", n, err)
	}
	if _, err := ngrokOptions(Options{Extra: map[string]string{"url": "https://x.ngrok.app"}}); err == nil {
		t.Fatal("non-tls endpoint accepted (would be edge-terminated)")
	}
	if u, _ := publicURLFromTLS("tls://pact.ngrok.app:443"); u != "https://pact.ngrok.app" {
		t.Fatalf("url: %s", u)
	}
	if u, _ := publicURLFromTLS("tls://pact.ngrok.app:8443"); u != "https://pact.ngrok.app:8443" {
		t.Fatalf("url: %s", u)
	}
	if edge, err := derivesEdge(t, "ngrok"); err != nil || edge {
		t.Fatal("ngrok tls endpoint must be direct mode")
	}
}

// AC: listener wrapping — the adapter hands back the raw stream and the node's
// own TLS runs on it, client certificate visible. A local net.Listener stands
// in for the ngrok endpoint.
func TestNgrokWrapsRawListenerForNodeTLS(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &Ngrok{opts: ngrokOpts{AuthToken: "tok", URL: "tls://", Name: "pact"},
		listen: func(context.Context, ngrokOpts) (net.Listener, string, error) {
			return local, "tls://pact.ngrok.app:443", nil
		}}
	info, err := a.Start(context.Background())
	if err != nil || info.TerminatesAtEdge || info.Listener == nil || info.PublicURL != "https://pact.ngrok.app" {
		t.Fatalf("info: %+v %v", info, err)
	}
	// the node runs its own TLS over the delivered stream
	nodeKP, _ := identity.Generate(identity.AlgoP256)
	nodeDER, _ := identity.SelfSignedCert(nodeKP, "node")
	tln := tls.NewListener(info.Listener, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{nodeDER}, PrivateKey: nodeKP.Signer}},
		ClientAuth:   tls.RequestClientCert,
	})
	seen := make(chan string, 1)
	go func() {
		c, err := tln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			seen <- "handshake: " + err.Error()
			return
		}
		f := "none"
		if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
			f, _ = identity.Fingerprint(certs[0].PublicKey)
		}
		seen <- f
	}()
	callerKP, _ := identity.Generate(identity.AlgoEd25519)
	callerDER, _ := identity.SelfSignedCert(callerKP, "caller")
	conn, err := tls.Dial("tcp", local.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{callerDER}, PrivateKey: callerKP.Signer}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "x")
	select {
	case f := <-seen:
		if f != callerKP.Fingerprint {
			t.Fatalf("node saw %q, want caller cert %s", f, callerKP.Fingerprint)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no handshake")
	}
	conn.Close()
	if st := a.Status(); !st.Running || st.PublicURL != "https://pact.ngrok.app" {
		t.Fatalf("status: %+v", st)
	}
	if err := a.Stop(); err != nil || a.Status().Running {
		t.Fatalf("stop: %v", err)
	}
	if _, err := local.Accept(); err == nil {
		t.Fatal("listener still open after Stop")
	}
}

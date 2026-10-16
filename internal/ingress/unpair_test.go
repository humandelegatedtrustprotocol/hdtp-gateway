package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/tunnel"
)

// An unpaired node's live session loses its subdomain at once, and the node paired on that name
// next is the one its callers reach. The plugin checked credentials only at Login and NewProxy, so
// the old node's session kept the vhost route after `ingress unpair`: every dial went to it, and
// the new node's proxy could not register the name the old one still held.
func TestAnUnpairedNodeLosesItsRouteToTheNextPairing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := NewMemoryRegistry(nil)
	dp := &DataPlane{Registry: reg, Domain: "example.test", BindAddr: "127.0.0.1",
		BindPort: freePort(t), VhostHTTPSPort: freePort(t), Token: "dp-token"}
	if err := dp.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer dp.Stop()

	connect := func(name, sub, secret string) {
		kp, cert := keypairCert(t, name)
		ln := nodeListener(t, name, cert)
		if err := reg.Put(Node{Fingerprint: kp.Fingerprint, SPKI: []byte{1}, Subdomain: sub, Mode: ModePassthrough, Secret: secret}); err != nil {
			t.Fatal(err)
		}
		a, err := tunnel.New("frp", tunnel.Options{PublicBind: ln.Addr().String(), Extra: map[string]string{
			"server_addr": "127.0.0.1", "server_port": strconv.Itoa(dp.BindPort), "token": "dp-token",
			"proxy_type": "https", "custom_domain": sub + ".example.test", "name": name,
			"meta_" + MetaNode: kp.Fingerprint, "meta_" + MetaSecret: secret,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Start(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Stop() })
	}
	// dial answers the name of the node that served sub, or "" when none did
	dial := func(sub string) string {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp",
			net.JoinHostPort(dp.BindAddr, fmt.Sprint(dp.VhostHTTPSPort)),
			&tls.Config{ServerName: sub + ".example.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		if err != nil {
			return ""
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		b, _ := io.ReadAll(conn)
		name, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
		return name
	}
	until := func(sub, want string, wait time.Duration) {
		t.Helper()
		got := ""
		for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if got = dial(sub); got == want {
				return
			}
		}
		t.Fatalf("%s reached %q, want %q", sub, got, want)
	}

	connect("oldnode", "alpha", "secret-old")
	connect("bystander", "beta", "secret-beta")
	until("alpha", "oldnode", 15*time.Second)
	until("beta", "bystander", 15*time.Second)

	if err := dp.Unpair("alpha"); err != nil {
		t.Fatal(err)
	}
	// the work connection the old node pooled before the unpair is not one more way in
	for i := range 3 {
		if got := dial("alpha"); got != "" {
			t.Fatalf("dial %d after the unpair reached %q", i, got)
		}
	}
	// the control: a session whose pairing stands is not cut
	if got := dial("beta"); got != "bystander" {
		t.Fatalf("beta reached %q right after alpha's unpair, want bystander", got)
	}

	connect("newnode", "alpha", "secret-new")
	until("alpha", "newnode", 15*time.Second)
	for i := range 5 {
		if got := dial("alpha"); got != "newnode" {
			t.Fatalf("dial %d after the re-pair reached %q, want newnode", i, got)
		}
	}
}

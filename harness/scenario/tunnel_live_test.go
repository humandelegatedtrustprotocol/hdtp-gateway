package scenario

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/fabric"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/images"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/registry"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/harness/topology"
)

// T6 — a node behind a self-hosted `frps`.
//
// This is the one live-reachability case that needs no account. Tailscale Funnel
// and ngrok's TLS endpoints both require one, so they stay owner-only runs; frp's
// server half is self-hostable, and `internal/tunnel/frp.go` imports frp/client —
// it IS the frpc side — so pointing it at a real frps exercises the adapter
// against the software it was written for rather than a stand-in.
//
// The property that matters: frps forwards RAW BYTES and routes by SNI, so the
// node's own certificate must reach the caller. A tunnel that terminated TLS
// would break mTLS identity, which is the whole basis of HDTP §2.
func TestNodeIsReachableThroughSelfHostedFrps(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "T6", Name: "a node behind a self-hosted frps keeps its own chain and serves MCP", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 10 * time.Minute,
	})

	const domain = "alice.harness.test"
	f := w.Fab
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// frps needs a CONFIG FILE. The image reads /etc/frp/frps.toml and ignores CLI
	// flags — passing --vhost_https_port had no effect and no error, and the only
	// symptom was the https vhost silently missing from its startup log three
	// steps later.
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "frps.toml"), []byte(
		"bindPort = 7000\nvhostHTTPSPort = 8443\nauth.method = \"token\"\n"+
			"auth.token = \"harness-token\"\nlog.level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	frps, err := f.Container(ctx, fabric.Spec{
		Name: "frps", Image: images.Frps, Network: net,
		Volumes: []string{filepath.Join(cfgDir, "frps.toml") + ":/etc/frp/frps.toml:ro"},
	})
	if err != nil {
		t.Fatalf("starting frps: %v", err)
	}
	// The https vhost must actually be listening, or a proxy of type https can
	// never register and the failure surfaces far from its cause.
	if err := waitLog(ctx, f, frps, "https service listen", 60*time.Second); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", frps.Name)
		t.Fatalf("frps has no https vhost: %v\n%s", err, shorten(string(out), 400))
	}
	if err := waitLog(ctx, f, frps, "frps started successfully", 60*time.Second); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", frps.Name)
		t.Fatalf("frps never started: %v\n%s", err, shorten(string(out), 500))
	}

	// The node starts in DIRECT mode. Adapter settings live in the settings store,
	// not the environment — `tunnel=frp` with none of them refuses to start with
	// "frp needs server_addr (your frps host)" — so the real journey is: bring the
	// node up, configure the adapter in the portal, then switch the tunnel on.
	// That is what an owner does, so it is what this exercises.
	//
	// Its public URL is the tunnel's from the start, because the account's leaf names the
	// address it answers at (HDTP §2) and the wallet signs it before the tunnel exists.
	//
	// Settings are the owner's, and the portal requires a session on every bind (SPEC §8.3):
	// so the owner registers a passkey (World.Node does), and sets them as that owner. This
	// posted forms as nobody, with a CSRF cookie read off an unauthenticated GET, while a
	// loopback bind needed no session; every POST has been refused since, three steps before
	// the symptom.
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net, PublicURL: "https://" + domain + ":8443"})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	node, bridge, owner, pin, aliceWallet := alice.Node, alice.Bridge, alice.Portal, alice.Pin, alice.Wallet
	if want := "https://" + domain + ":8443/a/alice/mcp"; pin.Endpoint != want {
		t.Fatalf("the leaf names %q, want the tunnel's address %q", pin.Endpoint, want)
	}
	for k, v := range map[string]string{
		"tunnel.frp.server_addr":   frps.Name,
		"tunnel.frp.server_port":   "7000",
		"tunnel.frp.token":         "harness-token",
		"tunnel.frp.proxy_type":    "https",
		"tunnel.frp.custom_domain": domain,
		"tunnel.frp.vhost_port":    "8443",
	} {
		if err := owner.PostForm(ctx, "/settings/adapter", "", map[string]string{"key": k, "value": v}); err != nil {
			t.Fatalf("setting %s through the portal: %v", k, err)
		}
	}
	if err := owner.PostForm(ctx, "/settings", "", map[string]string{
		"tunnel": "frp", "public_url": "https://" + domain + ":8443",
	}); err != nil {
		t.Fatalf("enabling the tunnel: %v", err)
	}

	// `tunnel` is restart-scoped: it owns a socket and a goroutine.
	if _, err := f.Raw(ctx, "docker", "restart", node.Name); err != nil {
		t.Fatal(err)
	}
	if err := topology.WaitHealthy(ctx, f, node); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Raw(ctx, "docker", "restart", bridge.Name); err != nil {
		t.Fatal(err)
	}

	// frps must accept the proxy, or nothing downstream means anything.
	if err := waitLog(ctx, f, frps, "new proxy [hdtp] type [https] success", 90*time.Second); err != nil {
		nl, _ := f.Raw(ctx, "docker", "logs", node.Name)
		sl, _ := f.Raw(ctx, "docker", "logs", frps.Name)
		t.Fatalf("frps never registered the node's proxy: %v\nnode: %s\nfrps: %s",
			err, shorten(string(nl), 400), shorten(string(sl), 400))
	}

	// A peer resolves the public name to frps and dials it. What comes back must
	// be the NODE's certificate: frps forwards raw bytes and routes by SNI, so an
	// end-to-end mTLS identity survives the hop.
	ip, err := f.Raw(ctx, "docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", frps.Name)
	if err != nil {
		t.Fatal(err)
	}
	frpsIP := strings.TrimSpace(string(ip))
	out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", net.Name,
		"--add-host", domain+":"+frpsIP, images.Alpine, "sh", "-c",
		"apk add -q openssl; echo | openssl s_client -showcerts -connect "+domain+":8443 -servername "+domain+" 2>&1")
	// What arrives must be the chain the node serves under — the leaf Alice's wallet issued,
	// byte for byte, then her root (HDTP §2, §14.2) — because that chain IS the identity a
	// caller validates, and a hop that re-terminated TLS would present something else. This
	// looked for `subject=CN=alice`, the lone self-signed certificate of a key-pinned node.
	var presented [][]byte
	for rest := out; ; {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			presented = append(presented, block.Bytes)
		}
		rest = tail
	}
	if len(presented) != 2 || !bytes.Equal(presented[0], pin.Leaf) || !bytes.Equal(presented[1], aliceWallet.RootDER) {
		t.Fatalf("the node's own chain did not survive the tunnel (%d certificate(s) presented) — "+
			"identity (HDTP §2) depends on it:\n%s", len(presented), shorten(string(out), 500))
	}
	t.Log("through frps: the leaf Alice's wallet issued, and her root, reached the caller")

	// And a real MCP call through the same tunnel. E14 hid for as long as it did
	// because no tunnel scenario ever made one: every messaging scenario runs
	// direct mode against a published port, where Host is 127.0.0.1 and the SDK's
	// rebinding guard is inert by construction. The plain `frp` adapter gets its
	// own regression guard here rather than relying on T5's ingress wrappers.
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"hdtp-harness","version":"1"}}}`
	body, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", net.Name,
		"--add-host", domain+":"+frpsIP, images.Curl,
		"-sS", "-k", "-m", "30", "-X", "POST",
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"--data", initialize, "https://"+domain+":8443/a/alice/mcp")
	if !strings.Contains(string(body), "protocolVersion") {
		t.Fatalf("an MCP call through the tunnel did not complete an initialize (E14 "+
			"regression — no tunnelled deployment can serve MCP when this breaks):\n%s",
			shorten(string(body), 600))
	}
	t.Log("through frps: a full MCP initialize completed against the node")
}

// waitLog polls a container's logs for a substring.
func waitLog(ctx context.Context, f *fabric.Fabric, c *fabric.Container, want string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		out, _ := f.Raw(ctx, "docker", "logs", c.Name)
		if strings.Contains(string(out), want) {
			return nil
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

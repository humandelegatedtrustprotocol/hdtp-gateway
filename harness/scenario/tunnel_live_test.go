package scenario

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/fabric"
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
// would break mTLS identity, which is the whole basis of PACT §2.
func TestNodeIsReachableThroughSelfHostedFrps(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	const domain = "alice.harness.test"
	f := fabric.New("pactfrp", dockerRun)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if dir := os.Getenv("PACT_HARNESS_ARTIFACTS"); dir != "" {
			_ = f.Collect(c, dir)
		}
		_ = f.Teardown(c)
	})

	net, err := f.Network(ctx, "net", fabric.NetOpts{})
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
		Name: "frps", Image: "snowdreamtech/frps:latest", Network: net,
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
	node, err := f.Container(ctx, fabric.Spec{
		Name: "node", Image: nodeImage, Network: net,
		Env: map[string]string{
			"PACT_PUBLIC_BIND":   "0.0.0.0:8443",
			"PACT_INTERNAL_BIND": "127.0.0.1:8080",
			"PACT_CLIENT_CERT":   "preferred",
		},
		Cmd: []string{"serve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := waitHealthyC(ctx, f, node); err != nil {
		t.Fatal(err)
	}
	if out, err := f.Exec(ctx, node, "/pact-gateway", "account", "create",
		"--slug", "alice", "--name", "Alice"); err != nil {
		t.Fatalf("account create: %v (%s)", err, out)
	}

	// The portal is loopback-bound (SPEC §8.3); a sidecar in the node's own netns
	// reaches it without the node binding non-loopback.
	bridge, err := f.Container(ctx, fabric.Spec{
		Name: "bridge", Image: "alpine/socat", NetworkMode: "container:" + node.Name,
		Cmd: []string{"TCP-LISTEN:8081,fork,reuseaddr", "TCP:127.0.0.1:8080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	// Reached by CONTAINER NAME on the harness network, not through a published
	// port: the bridge shares the node's namespace, so node:8081 is its listener.
	// (`--network host` does not reach published ports on Docker Desktop.)
	portal := "http://" + node.Name + ":8081"
	for k, v := range map[string]string{
		"tunnel.frp.server_addr":   frps.Name,
		"tunnel.frp.server_port":   "7000",
		"tunnel.frp.token":         "harness-token",
		"tunnel.frp.proxy_type":    "https",
		"tunnel.frp.custom_domain": domain,
		"tunnel.frp.vhost_port":    "8443",
	} {
		if err := postForm(ctx, f, net.Name, portal+"/settings/adapter", map[string]string{"key": k, "value": v}); err != nil {
			t.Fatalf("setting %s through the portal: %v", k, err)
		}
	}
	if err := postForm(ctx, f, net.Name, portal+"/settings", map[string]string{
		"tunnel": "frp", "public_url": "https://" + domain + ":8443",
	}); err != nil {
		t.Fatalf("enabling the tunnel: %v", err)
	}

	// `tunnel` is restart-scoped: it owns a socket and a goroutine.
	if _, err := f.Raw(ctx, "docker", "restart", node.Name); err != nil {
		t.Fatal(err)
	}
	if err := waitHealthyC(ctx, f, node); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Raw(ctx, "docker", "restart", bridge.Name); err != nil {
		t.Fatal(err)
	}

	// frps must accept the proxy, or nothing downstream means anything.
	if err := waitLog(ctx, f, frps, "new proxy [pact] type [https] success", 90*time.Second); err != nil {
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
		"--add-host", domain+":"+frpsIP, "alpine:3.20", "sh", "-c",
		"apk add -q openssl; echo | openssl s_client -connect "+domain+":8443 -servername "+domain+" 2>&1")
	got := string(out)
	if !strings.Contains(got, "subject=CN=alice") {
		t.Fatalf("the node's own certificate did not survive the tunnel — mTLS identity "+
			"(PACT §2) depends on it:\n%s", shorten(got, 500))
	}
	t.Log("through frps: the node's own CN=alice certificate reached the caller")

	// And a real MCP call through the same tunnel. E14 hid for as long as it did
	// because no tunnel scenario ever made one: every messaging scenario runs
	// direct mode against a published port, where Host is 127.0.0.1 and the SDK's
	// rebinding guard is inert by construction. The plain `frp` adapter gets its
	// own regression guard here rather than relying on T5's ingress wrappers.
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"pact-harness","version":"1"}}}`
	body, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", net.Name,
		"--add-host", domain+":"+frpsIP, curlImage,
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

// postForm submits a portal form from a throwaway container.
//
// The CSRF cookie is fetched and parsed in GO rather than in an inline shell
// script: the first version built one with nested quoting, the sed silently
// produced an empty token, every POST was rejected, and the failure surfaced
// three steps later as "frps never registered the node's proxy". Two plain docker
// runs are longer and debuggable.
func postForm(ctx context.Context, f *fabric.Fabric, network, url string, fields map[string]string) error {
	// The CSRF cookie comes from a page that certainly exists, derived from the
	// ORIGIN. Deriving it from the posted path worked only for /settings/* and
	// silently produced a 404 — and so an empty cookie — for anything else.
	origin := url
	if i := strings.Index(url[len("http://"):], "/"); i >= 0 {
		origin = url[:len("http://")+i]
	}
	base := origin + "/settings"
	head, err := f.Raw(ctx, "docker", "run", "--rm", "--network", network,
		"curlimages/curl:latest", "-s", "-i", "-m", "10", base)
	if err != nil {
		return fmt.Errorf("fetching the CSRF cookie: %w (%s)", err, shorten(string(head), 200))
	}
	csrf := ""
	for _, line := range strings.Split(string(head), "\n") {
		if !strings.Contains(strings.ToLower(line), "set-cookie: pact_csrf=") {
			continue
		}
		v := line[strings.Index(line, "pact_csrf=")+len("pact_csrf="):]
		if i := strings.IndexAny(v, ";\r"); i >= 0 {
			v = v[:i]
		}
		csrf = strings.TrimSpace(v)
	}
	if csrf == "" {
		return fmt.Errorf("no pact_csrf cookie from %s; the portal keeps CSRF on even on "+
			"a loopback bind, so a POST without it is refused", base)
	}

	args := []string{"run", "--rm", "--network", network, "curlimages/curl:latest",
		"-s", "-m", "15", "-X", "POST",
		"-H", "X-Pact-Csrf: " + csrf, "-b", "pact_csrf=" + csrf}
	for k, v := range fields {
		args = append(args, "--data-urlencode", k+"="+v)
	}
	// The BODY is kept: the portal explains a refusal in it — a missing
	// acknowledgment, a validation message — and discarding it left a bare "400"
	// with nothing to act on.
	args = append(args, url, "-w", "\nHTTP_STATUS:%{http_code}")
	out, err := f.Raw(ctx, "docker", args...)
	if err != nil {
		return fmt.Errorf("posting to %s: %w (%s)", url, err, shorten(string(out), 200))
	}
	body := string(out)
	code := ""
	if i := strings.LastIndex(body, "HTTP_STATUS:"); i >= 0 {
		code = strings.TrimSpace(body[i+len("HTTP_STATUS:"):])
		body = body[:i]
	}
	// Anything but 2xx/3xx means the setting did not land, and the consequences
	// only show up much later — so it fails here, where the cause is visible.
	if !strings.HasPrefix(code, "2") && !strings.HasPrefix(code, "3") {
		return fmt.Errorf("%s answered HTTP %s: %s", url, code, shorten(strings.TrimSpace(body), 400))
	}
	return nil
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

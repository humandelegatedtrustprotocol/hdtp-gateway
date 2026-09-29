package scenario

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/pact-cloud/pact-gateway/harness/fabric"
	"github.com/pact-cloud/pact-gateway/harness/images"
	"github.com/pact-cloud/pact-gateway/harness/peer"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/limits/limitstest"
)

// certHeader is the header Envoy forwards a caller's chain in (forward_client_cert_details); the
// node reads the same name (internal/integrationtest/envoy_test.go holds public.ProxyCertHeader to
// it). Named here rather than imported: internal/public would bring the node's whole dependency
// graph into this module for one string.
const certHeader = "X-Forwarded-Client-Cert"

// S23 — the node behind Envoy: the two layers of its rate limits, deployed the way
// deploy/envoy/compose.yaml deploys them (docs/release/two-layer-limits-2026-09-28.md, M-N1).
// Envoy runs this repository's deploy/envoy/envoy.yaml in the image that compose file pins
// (images.Envoy, held equal by harness/images); the node and its limits sidecar are the image under
// test with its shipped limits (topology.Serve). Every number below is read from those two files.
//
// Three callers, each a container with an address of its own on the network — a, b and c — and an
// agent in this process:
//   - layer 2 behind layer 1: a spends the node's per-source guest budget through Envoy and is
//     refused `rate_limited`, and still refused with an address header of its own forging (Envoy
//     replaced it); b, the control, is answered past the budget. A node that read Envoy's address
//     instead of the caller's, or the caller's header instead of Envoy's, puts a and b in one bucket
//     or lets a out of its own.
//   - the caller's chain: presented to Envoy, it reaches the node, whose answer to an unsealed call
//     is `seal_required` — what only a proven chain earns; forged as a header, through Envoy or
//     straight to the node, it proves nothing (`identity_required`).
//   - layer 1: c floods the MCP endpoint and the rest past their per-source buckets and Envoy
//     refuses it 429; b, the control, is let through on both.
//   - last, the control that changes the node's state: the agent's sealed request_contact, through
//     Envoy, is answered.
func TestTheNodeBehindEnvoyIsLimitedPerCallerAtBothLayers(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S23", Name: "the node behind Envoy: per-source floods refused at the edge and budgets behind it, a control through each; the caller's chain and address from Envoy alone; a sealed call answered", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage},
		Timeout: 10 * time.Minute,
	})
	edge := readEdge(t)
	perSource := int(limitstest.DefaultRules(t).GuestSourceCallsPerHour)
	if perSource < 1 {
		t.Fatalf("the shipped limits give a source %d calls an hour: nothing to spend", perSource)
	}
	if edge.upstreamPort != topology.PublicPort {
		t.Fatalf("envoy dials the node at port %d; the node listens at %d", edge.upstreamPort, topology.PublicPort)
	}

	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := fabric.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	// Callers reach the node by the name Envoy's certificate carries; the agent in this process
	// dials it at the published port (peer.Target.Dial), which is DNS's job for a real caller.
	const host = "edge.harness.example"
	tlsDir, _, pool := selfSignedCertificate(t, host)
	config, err := filepath.Abs(filepath.Join("..", "..", "deploy", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	envoy, err := w.Fab.Container(ctx, fabric.Spec{
		Name: "envoy", Image: images.Envoy, Network: net, Cmd: []string{"-c", "/etc/envoy/envoy.yaml"},
		Volumes: []string{config + ":/etc/envoy/envoy.yaml:ro", tlsDir + ":/etc/envoy/tls:ro"},
		Ports:   []string{fmt.Sprintf("%s:%d", port, edge.listenPort)},
	})
	if err != nil {
		t.Fatal(err)
	}
	envoyIP, err := w.Fab.IPOn(ctx, envoy, net)
	if err != nil {
		t.Fatal(err)
	}
	env := topology.NodeEnv("https://" + host + ":" + port)
	env["PACT_PROXY_ADDRESS"] = envoyIP
	env["PACT_SEAL"] = "required"
	node, err := topology.Serve(ctx, w.Fab, fabric.Spec{
		Name: "alice", Image: images.Node, Network: net, Env: env, Cmd: []string{"serve"},
		// The name envoy.yaml's cluster dials, as compose's service name is.
		Aliases: []string{edge.upstreamHost},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := topology.WaitHealthy(ctx, w.Fab, node); err != nil {
		t.Fatal(err)
	}
	_, pin, err := topology.Certify(ctx, w.Fab, node, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://" + host + ":" + port + "/a/alice/mcp"; pin.Endpoint != want {
		t.Fatalf("the leaf names %q, not the address Envoy answers at (%s)", pin.Endpoint, want)
	}

	agent, err := peer.NewAgent("caller")
	if err != nil {
		t.Fatal(err)
	}
	// The agent trusts Envoy's certificate as a caller trusts a WebPKI one (PACT §2's fallback).
	agent.Client.Roots = pool
	creds, chainPEM := callerCredentials(t, agent)
	card, err := json.Marshal(agent.Card("required"))
	if err != nil {
		t.Fatal(err)
	}
	a := startCaller(ctx, t, w, net, "a", creds)
	b := startCaller(ctx, t, w, net, "b", creds)
	c := startCaller(ctx, t, w, net, "c", creds)
	waitThroughEnvoy(ctx, t, host, port, pool)

	base := fmt.Sprintf("https://%s:%d", envoy.Name, edge.listenPort)
	mcpURL := base + "/a/alice/mcp"
	direct := fmt.Sprintf("https://%s:%d/a/alice/mcp", node.Name, topology.PublicPort)
	// An unsealed request_contact: substantive, so a node that requires sealing answers it
	// identity_required when no chain was proven and seal_required when one was, after the caller's
	// budget is spent (SPEC §5.7, §4.11).
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_contact","arguments":{"card":` +
		string(card) + `,"note":"S23"}}}`
	ask := func(from *fabric.Container, to string, extra ...string) string {
		t.Helper()
		return mcpCode(ctx, t, w, from, to, call, extra...)
	}

	// ── Layer 2 behind layer 1 ─────────────────────────────────────────────────────────────────
	for i := 1; i <= perSource; i++ {
		if got := ask(a, mcpURL); got != "identity_required" {
			t.Fatalf("a's call %d of the %d its source may make: %s, want identity_required", i, perSource, got)
		}
	}
	if got := ask(a, mcpURL); got != "rate_limited" {
		t.Errorf("a's call past its source's %d an hour: %s, want rate_limited", perSource, got)
	}
	// Forged before it is sent: an address of a's own choosing in the header the node reads.
	if got := ask(a, mcpURL, "-H", edge.addressHeader+": 203.0.113.7"); got != "rate_limited" {
		t.Errorf("a, naming another address in %s: %s, want rate_limited (Envoy must replace it)", edge.addressHeader, got)
	}
	if got := ask(b, mcpURL); got != "identity_required" {
		t.Errorf("b, the control, from an address that spent nothing: %s, want identity_required", got)
	}

	// ── The caller's chain comes from Envoy alone ──────────────────────────────────────────────
	if got := ask(b, mcpURL, "--cert", "/creds/chain.pem", "--key", "/creds/key.pem"); got != "seal_required" {
		t.Errorf("b presenting a chain to Envoy: %s, want seal_required (the chain proven at the node)", got)
	}
	forged := certHeader + `: Hash=00;Chain="` + url.PathEscape(chainPEM) + `"`
	if got := ask(b, mcpURL, "-H", forged); got != "identity_required" {
		t.Errorf("b sending a chain as a header through Envoy: %s, want identity_required", got)
	}
	if got := ask(b, direct, "-H", forged); got != "identity_required" {
		t.Errorf("b sending a chain as a header straight to the node: %s, want identity_required", got)
	}

	// ── Layer 1: Envoy, per source ─────────────────────────────────────────────────────────────
	mcpPost := []string{"-X", "POST", "-H", "Content-Type: application/json", "--data", "{}"}
	for _, r := range []struct {
		name   string
		bucket bucket
		url    string
		extra  []string
	}{
		{"the MCP endpoint", edge.mcp, mcpURL + "?n=", mcpPost},
		{"any other path", edge.other, base + "/flood/", nil},
	} {
		n := 2*r.bucket.max + r.bucket.max/2
		codes, took := flood(ctx, t, w, c, n, r.url, r.extra)
		// A bucket refills whole every interval, so a flood inside one interval meets at most two
		// buckets' worth of tokens: the full one it starts with, and one refill.
		if took >= r.bucket.every {
			t.Fatalf("UNREACHED: the flood of %s took %s, not within one refill (%s): its counts say nothing about the bucket", r.name, took, r.bucket.every)
		}
		refused := codes["429"]
		if codes["000"] > 0 {
			t.Fatalf("UNREACHED: %d of %d requests to %s never got an answer: %v", codes["000"], n, r.name, codes)
		}
		passed := n - refused
		if passed < r.bucket.max || passed > 2*r.bucket.max {
			t.Errorf("%s: %d of %d let through in %s, outside [%d, %d] for %d per %s: %v",
				r.name, passed, n, took, r.bucket.max, 2*r.bucket.max, r.bucket.max, r.bucket.every, codes)
		}
		if got := status(ctx, t, w, b, r.url+"control", r.extra); got == "429" || got == "000" {
			t.Errorf("b, the control, after c's flood of %s: %s", r.name, got)
		}
		t.Logf("S23: %s: c sent %d in %s, %d let through, %d refused 429 (%d per %s)", r.name, n, took.Round(time.Millisecond), passed, refused, r.bucket.max, r.bucket.every)
	}

	// ── The control that must get through: a sealed call, end to end through Envoy ───────────────
	target := peer.Target{Endpoint: pin.Endpoint, Dial: "127.0.0.1:" + port, Seal: "required", Root: pin.Root, Leaf: pin.Leaf}
	out, err := agent.Call(ctx, target, "request_contact", map[string]any{"card": agent.Card("required"), "note": "S23"}, "s23-request")
	if err != nil {
		t.Fatalf("the agent's sealed request_contact through Envoy: %v", err)
	}
	t.Logf("S23: the sealed request_contact through Envoy was answered %s", out)
}

// bucket is one route's per-source token bucket in envoy.yaml.
type bucket struct {
	max   int
	every time.Duration
}

// edgeConfig is what S23 reads from deploy/envoy/envoy.yaml.
type edgeConfig struct {
	listenPort   int
	upstreamHost string
	upstreamPort int
	// addressHeader is the header Envoy puts the caller's address in; the node reads the same
	// (internal/integrationtest/envoy_test.go holds public.ProxyAddressHeader to this file).
	addressHeader string
	mcp, other    bucket
}

// readEdge reads the proxy's numbers from the file Envoy runs, so there is no second copy of them.
func readEdge(t *testing.T) edgeConfig {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "envoy", "envoy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		StaticResources struct {
			Listeners []struct {
				Address struct {
					SocketAddress struct {
						PortValue int `json:"port_value"`
					} `json:"socket_address"`
				} `json:"address"`
				FilterChains []struct {
					Filters []struct {
						Name        string `json:"name"`
						TypedConfig struct {
							RouteConfig struct {
								RequestHeadersToAdd []struct {
									Header struct {
										Key string `json:"key"`
									} `json:"header"`
								} `json:"request_headers_to_add"`
								VirtualHosts []struct {
									Routes []struct {
										Match struct {
											Prefix    string `json:"prefix"`
											SafeRegex *struct {
												Regex string `json:"regex"`
											} `json:"safe_regex"`
										} `json:"match"`
										PerFilter map[string]struct {
											Descriptors []struct {
												TokenBucket struct {
													MaxTokens    int    `json:"max_tokens"`
													FillInterval string `json:"fill_interval"`
												} `json:"token_bucket"`
											} `json:"descriptors"`
										} `json:"typed_per_filter_config"`
									} `json:"routes"`
								} `json:"virtual_hosts"`
							} `json:"route_config"`
						} `json:"typed_config"`
					} `json:"filters"`
				} `json:"filter_chains"`
			} `json:"listeners"`
			Clusters []struct {
				LoadAssignment struct {
					Endpoints []struct {
						LbEndpoints []struct {
							Endpoint struct {
								Address struct {
									SocketAddress struct {
										Address   string `json:"address"`
										PortValue int    `json:"port_value"`
									} `json:"socket_address"`
								} `json:"address"`
							} `json:"endpoint"`
						} `json:"lb_endpoints"`
					} `json:"endpoints"`
				} `json:"load_assignment"`
			} `json:"clusters"`
		} `json:"static_resources"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var e edgeConfig
	sr := doc.StaticResources
	if len(sr.Listeners) != 1 || len(sr.Clusters) != 1 || len(sr.Clusters[0].LoadAssignment.Endpoints) != 1 ||
		len(sr.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints) != 1 {
		t.Fatal("deploy/envoy/envoy.yaml is not one listener in front of one node")
	}
	e.listenPort = sr.Listeners[0].Address.SocketAddress.PortValue
	up := sr.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints[0].Endpoint.Address.SocketAddress
	e.upstreamHost, e.upstreamPort = up.Address, up.PortValue
	for _, chain := range sr.Listeners[0].FilterChains {
		for _, f := range chain.Filters {
			if add := f.TypedConfig.RouteConfig.RequestHeadersToAdd; len(add) == 1 {
				e.addressHeader = add[0].Header.Key
			}
			for _, vh := range f.TypedConfig.RouteConfig.VirtualHosts {
				for _, r := range vh.Routes {
					rl := r.PerFilter["envoy.filters.http.local_ratelimit"]
					if len(rl.Descriptors) != 1 {
						continue
					}
					every, err := time.ParseDuration(rl.Descriptors[0].TokenBucket.FillInterval)
					if err != nil {
						t.Fatal(err)
					}
					bk := bucket{max: rl.Descriptors[0].TokenBucket.MaxTokens, every: every}
					switch {
					case r.Match.SafeRegex != nil && strings.HasSuffix(r.Match.SafeRegex.Regex, "/mcp$"):
						e.mcp = bk
					case r.Match.Prefix == "/":
						e.other = bk
					}
				}
			}
		}
	}
	if e.listenPort == 0 || e.upstreamHost == "" || e.addressHeader == "" || e.mcp.max < 1 || e.other.max < 1 || e.mcp.every <= 0 || e.other.every <= 0 {
		t.Fatalf("read %+v from deploy/envoy/envoy.yaml: not the listener, the node, the address header and the two buckets S23 floods", e)
	}
	return e
}

// callerCredentials writes the agent's chain (leaf first) and key where a caller's curl reads them,
// and returns the directory and the chain as PEM.
func callerCredentials(t *testing.T, agent *peer.Agent) (string, string) {
	t.Helper()
	der, err := identity.MarshalPKCS8(agent.Keypair)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agent.Keypair.Leaf})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agent.Keypair.Root}))
	dir := t.TempDir()
	// curl runs as an unprivileged user and must read both through the mount.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"chain.pem": []byte(chain),
		"key.pem":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil { //nolint:gosec // a test key the caller container must read
			t.Fatal(err)
		}
	}
	return dir, chain
}

// startCaller is a curl container that stays up, so it keeps one address for the whole scenario:
// a container started per request could be given an address another caller had.
func startCaller(ctx context.Context, t *testing.T, w *World, net *fabric.Network, name, creds string) *fabric.Container {
	t.Helper()
	c, err := w.Fab.Container(ctx, fabric.Spec{
		Name: name, Image: images.Curl, Network: net, Cmd: []string{"sleep", "1200"},
		Volumes: []string{creds + ":/creds:ro"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// waitThroughEnvoy polls the node through Envoy's published port until Envoy has found it: its
// cluster resolves the node's name on a timer, and until then it answers 503 itself.
func waitThroughEnvoy(ctx context.Context, t *testing.T, host, port string, pool *x509.CertPool) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12},
	}}
	deadline := time.Now().Add(90 * time.Second)
	last := "no answer"
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+port+"/", nil)
		req.Host = host
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("the node never answered through Envoy: %s", last)
}

// mcpCode POSTs one JSON-RPC request from a caller and returns the refusal code of its answer, "ok"
// for an answer that is not a refusal, or what came back instead.
func mcpCode(ctx context.Context, t *testing.T, w *World, from *fabric.Container, to, body string, extra ...string) string {
	t.Helper()
	args := []string{"curl", "-sk", "-m", "20", "-X", "POST",
		"-H", "Content-Type: application/json", "-H", "Accept: application/json, text/event-stream",
		"--data", body, "-w", "\n%{http_code}"}
	args = append(append(args, extra...), to)
	raw, err := w.Fab.Exec(ctx, from, args...)
	if err != nil {
		t.Fatalf("curl from %s: %v\n%s", from.Name, err, raw)
	}
	out := strings.TrimRight(string(raw), "\n")
	cut := strings.LastIndex(out, "\n")
	if cut < 0 {
		return "no status: " + out
	}
	text, code := out[:cut], out[cut+1:]
	if code != "200" {
		return "http " + code + ": " + shorten(text, 300)
	}
	// Streamable HTTP answers as JSON or as one server-sent event.
	payload := text
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, "data:"); ok {
			payload = strings.TrimSpace(rest)
		}
	}
	var rpc struct {
		Result *struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(payload), &rpc); err != nil || (rpc.Result == nil && rpc.Error == nil) {
		return "unreadable: " + shorten(text, 300)
	}
	if rpc.Error != nil {
		return "rpc error: " + rpc.Error.Message
	}
	if !rpc.Result.IsError {
		return "ok"
	}
	var refusal struct {
		Code string `json:"code"`
	}
	for _, c := range rpc.Result.Content {
		if json.Unmarshal([]byte(c.Text), &refusal) == nil && refusal.Code != "" {
			return refusal.Code
		}
	}
	return "error without a code: " + shorten(text, 300)
}

// flood sends n requests from one caller, ten at a time, to prefix followed by 1…n, and counts the
// status codes; took is the whole run, docker's exec included, so it errs long.
func flood(ctx context.Context, t *testing.T, w *World, from *fabric.Container, n int, prefix string, extra []string) (map[string]int, time.Duration) {
	t.Helper()
	args := []string{"curl", "-sk", "-m", "30", "--parallel", "--parallel-max", "10",
		"-o", "/dev/null", "-w", "%{http_code}\n"}
	args = append(append(args, extra...), prefix+"["+"1-"+strconv.Itoa(n)+"]")
	start := time.Now()
	raw, err := w.Fab.Exec(ctx, from, args...)
	took := time.Since(start)
	// curl exits non-zero when a transfer failed; those are counted as 000 below.
	codes := map[string]int{}
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if len(l) != 3 {
			t.Fatalf("the flood from %s printed %q, not a status per line (%v)", from.Name, shorten(l, 200), err)
		}
		codes[l]++
		lines++
	}
	if lines != n {
		t.Fatalf("the flood from %s answered %d of %d requests (%v): %v", from.Name, lines, n, err, codes)
	}
	return codes, took
}

// status is one request's status code from a caller.
func status(ctx context.Context, t *testing.T, w *World, from *fabric.Container, to string, extra []string) string {
	t.Helper()
	args := append([]string{"curl", "-sk", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}"}, extra...)
	raw, _ := w.Fab.Exec(ctx, from, append(args, to)...)
	return strings.TrimSpace(string(raw))
}

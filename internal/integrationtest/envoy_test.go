package integrationtest

// Layer 1 of the node's rate limits is a proxy's configuration (deploy/envoy/envoy.yaml) and a
// deployment's (deploy/envoy/compose.yaml), which only run against containers — the harness's S23
// does, with Docker. A configuration nothing reads between those runs goes stale silently, so this
// holds, on every commit, what the node relies on it for:
//   - the caller's chain reaches the node only as Envoy writes it: requested, accepted without an
//     authority, forwarded whole (SANITIZE_SET: a caller's own header is dropped, never appended to);
//   - the caller's address reaches the node as Envoy's socket saw it (use_remote_address), in the
//     header the node reads, replacing whatever the caller sent in it;
//   - every route is limited per source address, by a bucket of each address's own and no bucket
//     the sources share, and the listener's connections to the node's own cap
//     (public.DefaultMaxConns: two copies of one number);
//   - a request is held to the node listener's own bounds (hdtpnode.Public*: the headers, the request,
//     the answer, an idle connection, the size of the headers);
//   - the compose file's node trusts exactly the address envoy is given, is the upstream envoy
//     dials, and has its limits sidecar on the shared /data; only envoy is published.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	hdtpnode "github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/node"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
)

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// at walks a decoded document by map keys and list indexes; nil when the path is not there.
func at(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

// filterNamed is the filter of a chain whose name is name.
func filterNamed(filters any, name string) any {
	l, _ := filters.([]any)
	for _, f := range l {
		if at(f, "name") == name {
			return at(f, "typed_config")
		}
	}
	return nil
}

func envoyConfig(t *testing.T) (listener, hcm, cluster any) {
	t.Helper()
	doc := readYAML(t, filepath.Join(repoRoot(t), "deploy", "envoy", "envoy.yaml"))
	listener = at(doc, "static_resources", "listeners", 0)
	hcm = filterNamed(at(listener, "filter_chains", 0, "filters"), "envoy.filters.network.http_connection_manager")
	cluster = at(doc, "static_resources", "clusters", 0)
	if listener == nil || hcm == nil || cluster == nil {
		t.Fatal("deploy/envoy/envoy.yaml has no listener, connection manager or cluster where this test reads them")
	}
	return listener, hcm, cluster
}

func TestEnvoyForwardsTheCallersChainAndAddressAsTheNodeReadsThem(t *testing.T) {
	listener, hcm, _ := envoyConfig(t)
	tls := at(listener, "filter_chains", 0, "transport_socket", "typed_config")
	if at(tls, "require_client_certificate") != false || at(tls, "common_tls_context", "validation_context", "trust_chain_verification") != "ACCEPT_UNTRUSTED" {
		t.Error("envoy must request the caller's chain, require none, and accept any: there is no authority above the person (SPEC §5.1)")
	}
	if at(hcm, "forward_client_cert_details") != "SANITIZE_SET" {
		t.Errorf("forward_client_cert_details is %v: anything but SANITIZE_SET lets a caller's own X-Forwarded-Client-Cert reach the node", at(hcm, "forward_client_cert_details"))
	}
	if at(hcm, "set_current_client_cert_details", "chain") != true {
		t.Error("envoy must forward the whole chain (set_current_client_cert_details.chain): a leaf alone names no root")
	}
	if at(hcm, "use_remote_address") != true {
		t.Error("use_remote_address must be on: without it the caller's address is read from the caller's own X-Forwarded-For")
	}
	if public.ProxyCertHeader != "X-Forwarded-Client-Cert" {
		t.Errorf("the node reads the chain from %s; envoy forwards it in X-Forwarded-Client-Cert", public.ProxyCertHeader)
	}
	set := at(hcm, "route_config", "request_headers_to_add", 0)
	if key, _ := at(set, "header", "key").(string); !strings.EqualFold(key, public.ProxyAddressHeader) ||
		at(set, "header", "value") != "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%" ||
		at(set, "append_action") != "OVERWRITE_IF_EXISTS_OR_ADD" {
		t.Errorf("envoy must set %s to the address its socket saw, replacing the caller's: it sets %v", public.ProxyAddressHeader, set)
	}
}

func TestEnvoyLimitsEveryRoutePerSourceAddressAndHoldsTheNodesConnectionCap(t *testing.T) {
	listener, hcm, _ := envoyConfig(t)
	limit := filterNamed(at(listener, "filter_chains", 0, "filters"), "envoy.filters.network.connection_limit")
	if n, _ := at(limit, "max_connections").(float64); int(n) != public.DefaultMaxConns {
		t.Errorf("envoy holds %v connections; the node holds %d (public.DefaultMaxConns)", at(limit, "max_connections"), public.DefaultMaxConns)
	}
	routes, _ := at(hcm, "route_config", "virtual_hosts", 0, "routes").([]any)
	if len(routes) < 3 {
		t.Fatalf("read %d routes; the MCP endpoint, the invite landing and the rest are three", len(routes))
	}
	for i, r := range routes {
		rl := at(r, "typed_per_filter_config", "envoy.filters.http.local_ratelimit")
		key := at(rl, "descriptors", 0, "entries", 0, "key")
		action := at(rl, "rate_limits", 0, "actions", 0, "remote_address")
		tokens, _ := at(rl, "descriptors", 0, "token_bucket", "max_tokens").(float64)
		if key != "remote_address" || action == nil || tokens < 1 {
			t.Errorf("route %d (%v) is not limited per source address", i, at(r, "match"))
		}
		if at(rl, "filter_enforced", "default_value", "numerator") != float64(100) {
			t.Errorf("route %d's limit is not enforced on every request", i)
		}
		// Envoy's own default spends the route's bucket on every request as well as the address's,
		// which makes it one bucket all sources share: one flood would refuse everybody.
		if at(rl, "always_consume_default_token_bucket") != false {
			t.Errorf("route %d spends a bucket every source shares (always_consume_default_token_bucket is not false)", i)
		}
	}
	// The limit filter is in the chain, ahead of the router.
	filters, _ := at(hcm, "http_filters").([]any)
	if len(filters) < 2 || at(filters[0], "name") != "envoy.filters.http.local_ratelimit" || at(filters[len(filters)-1], "name") != "envoy.filters.http.router" {
		t.Error("the local rate limit must run before the router")
	}
}

func TestTheEnvoyComposeTrustsEnvoyAloneAndRunsTheSidecar(t *testing.T) {
	_, _, cluster := envoyConfig(t)
	doc := readYAML(t, filepath.Join(repoRoot(t), "deploy", "envoy", "compose.yaml"))
	services, _ := at(doc, "services").(map[string]any)
	node, envoy, limitd := services["node"], services["envoy"], services["limitd"]
	if node == nil || envoy == nil || limitd == nil {
		t.Fatal("deploy/envoy/compose.yaml has no node, envoy or limitd service")
	}
	if proxy := at(node, "environment", "HDTP_PROXY_ADDRESS"); proxy == nil || proxy != at(envoy, "networks", "edge", "ipv4_address") {
		t.Errorf("the node trusts %v; envoy is at %v", proxy, at(envoy, "networks", "edge", "ipv4_address"))
	}
	// Envoy dials the node by its service name, at the port the node listens on.
	upstream := at(cluster, "load_assignment", "endpoints", 0, "lb_endpoints", 0, "endpoint", "address", "socket_address")
	bind, _ := at(node, "environment", "HDTP_PUBLIC_BIND").(string)
	port, _ := at(upstream, "port_value").(float64)
	if at(upstream, "address") != "node" || !strings.HasSuffix(bind, ":"+strconv.Itoa(int(port))) {
		t.Errorf("envoy dials %v:%v; the node binds %q", at(upstream, "address"), at(upstream, "port_value"), bind)
	}
	for name, s := range services {
		if name != "envoy" && at(s, "ports") != nil {
			t.Errorf("%s publishes a port: behind envoy, only envoy is reached from outside", name)
		}
	}
	// The sidecar: the image's /hdtp-limitd, sharing the /data the node's socket is in.
	if at(limitd, "entrypoint", 0) != "/hdtp-limitd" || at(limitd, "volumes", 0) != at(node, "volumes", 0) {
		t.Error("the limits sidecar must run /hdtp-limitd on the node's /data volume")
	}
	limitdHealthcheckAsksTheSidecar(t, "deploy/envoy/compose.yaml", limitd)
}

func TestEnvoyHoldsARequestToTheListenersOwnBounds(t *testing.T) {
	_, hcm, _ := envoyConfig(t)
	duration := func(v any) time.Duration {
		d, _ := time.ParseDuration(func() string { s, _ := v.(string); return s }())
		return d
	}
	for _, c := range []struct {
		what string
		got  time.Duration
		want time.Duration
	}{
		{"request_headers_timeout", duration(at(hcm, "request_headers_timeout")), hdtpnode.PublicHeaderTimeout},
		{"request_timeout", duration(at(hcm, "request_timeout")), hdtpnode.PublicRequestTimeout},
		{"common_http_protocol_options.idle_timeout", duration(at(hcm, "common_http_protocol_options", "idle_timeout")), hdtpnode.PublicIdleTimeout},
	} {
		if c.got != c.want {
			t.Errorf("envoy's %s is %s; the node's listener holds %s", c.what, c.got, c.want)
		}
	}
	if kb, _ := at(hcm, "max_request_headers_kb").(float64); int(kb)<<10 != hdtpnode.PublicMaxHeaderBytes {
		t.Errorf("envoy takes %v KiB of headers; the node's listener takes %d bytes", at(hcm, "max_request_headers_kb"), hdtpnode.PublicMaxHeaderBytes)
	}
	routes, _ := at(hcm, "route_config", "virtual_hosts", 0, "routes").([]any)
	for i, r := range routes {
		if got := duration(at(r, "route", "timeout")); got != hdtpnode.PublicAnswerTimeout {
			t.Errorf("route %d (%v) waits %s for the node's answer; the node's listener gives it %s", i, at(r, "match"), got, hdtpnode.PublicAnswerTimeout)
		}
	}
}

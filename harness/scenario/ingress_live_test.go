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

// T5 — the owner's own front door (SPEC §10.6), with a real ACME CA.
//
// Everything about the ingress role was tested in-process: internal/ingress has
// unit tests for pairing, SNI routing and the terminator, and
// TestP5ExitOwnDomainPassthroughAndTerminate drives Pebble and a stub resolver on
// loopback. What NOTHING ran was `ingress serve` — the 200-line function that
// assembles the role from flags. `relaywiring_test.go` only checks the arguments
// it REFUSES, which exits before anything is built. That is the same gap that hid
// P14-05c (AddMembership had zero production callers) and P14-03a (the image
// could not build): a library that is correct and a binary nobody executes.
//
// So this runs the real binary in the real role, on its own host, against a
// containerised CA and an authoritative zone, and asserts the two properties that
// make the two modes different from each other:
//
//	passthrough — the caller must receive the NODE's certificate. The ingress
//	  splices raw bytes on SNI and cannot read the session (SPEC §3.8).
//	terminate   — the caller must receive a CA-ISSUED certificate for the public
//	  name, verifying against the CA's root with no exception, and the request
//	  must still arrive at the node behind it.
//
// It is a scenario file rather than a topology because, like T6, the scaffolding
// (a CA, a zone) is specific to this shape and not a network the others reuse.
// pebbleConfig is the image's own config with the paths it expects. Only the
// HTTP-01 port is changed, by the caller, from Pebble's deliberately non-standard
// 5002 to the 80 a real CA uses.
const pebbleConfig = `{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": {"authz": 1, "order": 1},
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {"description": "harness", "validityPeriod": 7776000}
    }
  }
}`

func TestOwnDomainIngressServesPassthroughAndTerminate(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const domain = "harness.test"
	f := fabric.New("pactt5", dockerRun)
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

	// Pebble's own https uses a bundled certificate whose SANs are localhost and
	// `pebble`, signed by a root that ships in the same image. Taking both from
	// the image guarantees the root we trust is the one the running server uses.
	assets := t.TempDir()
	caRoot := filepath.Join(assets, "pebble-root.pem")
	if err := copyFromImage(ctx, f, pebbleImage, "/test/certs/pebble.minica.pem", caRoot); err != nil {
		t.Fatalf("taking Pebble's root out of its image: %v", err)
	}

	// --- the ingress: the real binary, in the ingress role ---
	//
	// -acme-ca and -acme-ca-root are the flags P14-06 added. Without them the
	// role could only ever talk to Let's Encrypt production, so this scenario
	// could not exist and neither could an owner's rehearsal.
	ing, err := f.Container(ctx, fabric.Spec{
		Name: "ingress", Image: nodeImage, Network: net,
		Volumes: []string{caRoot + ":/pebble-root.pem:ro"},
		Env:     map[string]string{"PACT_INGRESS_TOKEN": "harness-dp"},
		Cmd: []string{"ingress", "serve",
			"-domain", domain,
			"-data-dir", "/tmp/ingress",
			"-pair-bind", "0.0.0.0:8444",
			"-vhost-port", "443",
			"-data-plane-port", "7000",
			"-terminate",
			"-acme-email", "owner@harness.test",
			"-acme-dir", "/tmp/acme",
			"-acme-ca", "https://pebble:14000/dir",
			"-acme-ca-root", "/pebble-root.pem",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := waitLog(ctx, f, ing, "public:   :443", 90*time.Second); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", ing.Name)
		t.Fatalf("the ingress role never came up: %v\n%s", err, shorten(string(out), 600))
	}
	ingIP, err := containerIP(ctx, f, ing)
	if err != nil {
		t.Fatal(err)
	}

	// --- an authoritative zone for harness.test, pointing every name at it ---
	//
	// The CA resolves the challenge name itself, so a hosts entry would not do:
	// HTTP-01 is only meaningful if the name genuinely resolves to the host that
	// answers the challenge.
	if err := os.WriteFile(filepath.Join(assets, "Corefile"),
		[]byte(domain+":53 {\n    file /etc/coredns/zone\n    log\n    errors\n}\n"+
			// Anything outside the zone still has to resolve, or a container told
			// to use this resolver loses the rest of the internet — which is how
			// the first run failed, three steps from the cause.
			".:53 {\n    forward . 127.0.0.11\n    errors\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zone := fmt.Sprintf("$ORIGIN %s.\n$TTL 60\n"+
		"@   IN SOA ns.%s. owner.%s. 1 60 60 60 60\n"+
		"@   IN NS  ns.%s.\n"+
		"ns  IN A %s\n@ IN A %s\ningress IN A %s\nalice IN A %s\nbob IN A %s\n",
		domain, domain, domain, domain, ingIP, ingIP, ingIP, ingIP, ingIP)
	if err := os.WriteFile(filepath.Join(assets, "zone"), []byte(zone), 0o644); err != nil {
		t.Fatal(err)
	}
	dnsc, err := f.Container(ctx, fabric.Spec{
		Name: "dns", Image: corednsImage, Network: net,
		Volumes: []string{
			filepath.Join(assets, "Corefile") + ":/etc/coredns/Corefile:ro",
			filepath.Join(assets, "zone") + ":/etc/coredns/zone:ro",
		},
		Cmd: []string{"-conf", "/etc/coredns/Corefile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dnsIP, err := containerIP(ctx, f, dnsc)
	if err != nil {
		t.Fatal(err)
	}
	// CoreDNS EXITS on a malformed Corefile. The container is still inspectable
	// for a moment afterwards, so an unchecked start looks like success and the
	// consequence arrives four minutes later as "the ingress never obtained a
	// certificate" — which is where the first version of this failed. A written
	// zone that nobody has resolved is not a zone.
	if err := waitZone(ctx, f, net.Name, dnsIP, "bob."+domain, ingIP, 60*time.Second); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", dnsc.Name)
		t.Fatalf("the authoritative zone never answered: %v\n%s", err, shorten(string(out), 400))
	}

	// --- the CA ---
	//
	// Pebble's stock config puts HTTP-01 on 5002, which is deliberate upstream and
	// wrong here: the ingress's solver listens on 80 because that is the only port
	// a real CA will ever use. The config is rewritten rather than the product
	// bent to fit the test.
	cfg := strings.NewReplacer("5002", "80").Replace(pebbleConfig)
	if err := os.WriteFile(filepath.Join(assets, "pebble.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	peb, err := f.Container(ctx, fabric.Spec{
		Name: "pebble", Image: pebbleImage, Network: net,
		// The bundled certificate's SAN is the bare name `pebble`; the run prefix
		// keeps teardown safe, and the alias makes both true at once.
		Aliases: []string{"pebble"},
		Volumes: []string{filepath.Join(assets, "pebble.json") + ":/pebble.json:ro"},
		Env: map[string]string{
			"PEBBLE_VA_NOSLEEP":      "1", // no random validation delay
			"PEBBLE_WFE_NONCEREJECT": "0", // no 5% nonce chaos: this is not a client conformance run
		},
		Cmd: []string{"-config", "/pebble.json", "-dnsserver", dnsIP + ":53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := waitLog(ctx, f, peb, "ACME directory available", 60*time.Second); err != nil {
		out, _ := f.Raw(ctx, "docker", "logs", peb.Name)
		t.Fatalf("the CA never came up: %v\n%s", err, shorten(string(out), 500))
	}

	// Pebble generates its issuance root AT STARTUP — `pebble.minica.pem` is only
	// the root for Pebble's own https listener, which is what -acme-ca-root needs.
	// The certificate the ingress serves chains to the generated one, published by
	// the management interface, and verifying against the wrong root would fail in
	// a way that looks exactly like a broken onward leg.
	issuanceRoot := filepath.Join(assets, "issuance-root.pem")
	pem, err := f.Raw(ctx, "docker", "run", "--rm", "--network", net.Name, curlImage,
		"-sS", "-k", "-m", "20", "https://"+peb.Name+":15000/roots/0")
	if err != nil || !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Fatalf("could not fetch the CA's issuance root: %v (%s)", err, shorten(string(pem), 200))
	}
	if err := os.WriteFile(issuanceRoot, pem, 0o644); err != nil {
		t.Fatal(err)
	}

	// --- two nodes, one per mode ---
	type nodeCase struct {
		slug, mode string
		container  *fabric.Container
		bridge     *fabric.Container
	}
	cases := []*nodeCase{{slug: "alice", mode: "passthrough"}, {slug: "bob", mode: "terminate"}}
	for _, nc := range cases {
		c, err := f.Container(ctx, fabric.Spec{
			Name: nc.slug, Image: nodeImage, Network: net,
			DNS: []string{dnsIP},
			Env: map[string]string{
				"PACT_PUBLIC_BIND":   "0.0.0.0:8443",
				"PACT_INTERNAL_BIND": "127.0.0.1:8080",
				"PACT_CLIENT_CERT":   "preferred",
				"PACT_SEAL":          "optional",
			},
			Cmd: []string{"serve"},
		})
		if err != nil {
			t.Fatal(err)
		}
		nc.container = c
		if err := waitHealthyC(ctx, f, c); err != nil {
			t.Fatal(err)
		}
		if out, err := f.Exec(ctx, c, "/pact-gateway", "account", "create",
			"--slug", nc.slug, "--name", strings.ToUpper(nc.slug[:1])+nc.slug[1:]); err != nil {
			t.Fatalf("account create on %s: %v (%s)", nc.slug, err, out)
		}
		b, err := f.Container(ctx, fabric.Spec{
			Name: nc.slug + "-bridge", Image: socatImage, NetworkMode: "container:" + c.Name,
			Cmd: []string{"TCP-LISTEN:8081,fork,reuseaddr", "TCP:127.0.0.1:8080"},
		})
		if err != nil {
			t.Fatal(err)
		}
		nc.bridge = b
	}
	time.Sleep(2 * time.Second)

	// --- pairing: a one-time token per node, redeemed through the portal ---
	//
	// The pair URL is the container name, not a public one: Pair pins the ingress
	// by SPKI fingerprint and skips chain and hostname verification entirely
	// (PACT §2), so the name it is reached by carries no trust.
	for _, nc := range cases {
		tok, err := f.Exec(ctx, ing, "/pact-gateway", "ingress", "token", "-data-dir", "/tmp/ingress")
		if err != nil {
			t.Fatalf("minting a pairing token: %v (%s)", err, tok)
		}
		portal := "http://" + nc.container.Name + ":8081"
		if err := postForm(ctx, f, net.Name, portal+"/settings/pair", map[string]string{
			"pair_url":  "https://" + ing.Name + ":8444/pair",
			"token":     strings.TrimSpace(string(tok)),
			"subdomain": nc.slug,
			"mode":      nc.mode,
		}); err != nil {
			t.Fatalf("pairing %s: %v", nc.slug, err)
		}
		adapter := "ingress-" + nc.mode
		if err := postForm(ctx, f, net.Name, portal+"/settings", map[string]string{
			"tunnel": adapter, "public_url": "https://" + nc.slug + "." + domain,
		}); err != nil {
			t.Fatalf("switching %s to %s: %v", nc.slug, adapter, err)
		}
	}

	// A terminate pairing triggers issuance on the ingress. If the CA refuses, the
	// handshake later fails inside TLS where no handler ever sees it — so it is
	// caught here, at its cause.
	if err := waitLog(ctx, f, ing, "acme_manage name:bob."+domain+" ok", 4*time.Minute); err != nil {
		il, _ := f.Raw(ctx, "docker", "logs", ing.Name)
		pl, _ := f.Raw(ctx, "docker", "logs", peb.Name)
		t.Fatalf("the ingress never obtained a certificate for bob.%s: %v\ningress: %s\nca: %s",
			domain, err, shorten(string(il), 700), shorten(string(pl), 500))
	}

	// `tunnel` is restart-scoped: it owns a socket and a goroutine.
	for _, nc := range cases {
		if _, err := f.Raw(ctx, "docker", "restart", nc.container.Name); err != nil {
			t.Fatal(err)
		}
		if err := waitHealthyC(ctx, f, nc.container); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Raw(ctx, "docker", "restart", nc.bridge.Name); err != nil {
			t.Fatal(err)
		}
	}
	// Both adapters dial OUT to the data plane; until the ingress has registered
	// them there is nothing behind either name.
	for _, nc := range cases {
		if err := waitLog(ctx, f, ing, "ingress_proxy subdomain:"+nc.slug+" ok", 2*time.Minute); err != nil {
			il, _ := f.Raw(ctx, "docker", "logs", ing.Name)
			nl, _ := f.Raw(ctx, "docker", "logs", nc.container.Name)
			t.Fatalf("%s never attached to the data plane: %v\ningress: %s\nnode: %s",
				nc.slug, err, shorten(string(il), 700), shorten(string(nl), 500))
		}
	}

	// --- what the caller receives, per mode ---

	// Passthrough: the node's OWN certificate. The ingress forwards bytes on SNI
	// and never holds a key for this name, so anything else means it terminated
	// and the end-to-end mTLS identity of PACT §2 is gone.
	got := chainSeen(ctx, f, net.Name, dnsIP, "alice."+domain)
	if !strings.Contains(got, "subject: CN=alice") {
		il, _ := f.Raw(ctx, "docker", "logs", ing.Name)
		nl, _ := f.Raw(ctx, "docker", "logs", cases[0].container.Name)
		t.Errorf("passthrough did not preserve the node's own certificate — the ingress "+
			"terminated a session it must not be able to read:\n%s\ningress: %s\nnode: %s",
			shorten(got, 600), shorten(string(il), 900), shorten(string(nl), 500))
	}

	// Terminate: a CA-issued certificate for the PUBLIC name, verified against the
	// CA's real root with NO exception. Verification is the assertion — it proves
	// the chain and the name together — because Pebble, like Boulder, issues with
	// no CN at all and only a subjectAltName, so matching a subject string would
	// be checking the wrong field.
	got = chainVerified(ctx, f, net.Name, dnsIP, issuanceRoot, "bob."+domain)
	if strings.Contains(got, "SSL certificate problem") || strings.Contains(got, "TLS connect error") {
		t.Fatalf("the certificate for bob.%s does not verify against the CA that issued "+
			"it, so terminate mode serves nothing a browser would accept:\n%s", domain, shorten(got, 700))
	}
	if !strings.Contains(got, "Pebble") {
		t.Errorf("the certificate did not come from the ACME CA, so nothing here "+
			"exercised issuance:\n%s", shorten(got, 700))
	}

	// And the terminated request must REACH the node. The ingress speaks no HTTP
	// at all — it hands the decrypted stream to a separate TLS leg — so a PACT
	// error body can only have been written by bob's own handler.
	body := mcpInitialize(ctx, f, net.Name, dnsIP, issuanceRoot, "https://bob."+domain+"/a/bob/mcp")
	if !strings.Contains(body, `"code"`) && !strings.Contains(body, "protocolVersion") {
		t.Fatalf("the terminated request never reached bob at all; the ingress's onward "+
			"mutually-pinned leg is what carries it (SPEC §10.6):\n%s", shorten(body, 600))
	}

	// E13 and E14, both fixed and both pinned here at their default settings — no
	// flag is relaxed to make this pass.
	//
	// E13: pairing in terminate mode derives edge mode, which defaults
	// lan_connections off, and the adapter delivers the ingress's leg to the node's
	// public bind from loopback. While loopback counted as LAN, every edge-mode
	// deployment refused its own connector. E14: the MCP SDK auto-enables
	// DNS-rebinding protection for a loopback socket with a non-loopback Host,
	// which is precisely what a reverse tunnel produces, so every tunnelled MCP
	// call was refused.
	if !strings.Contains(body, "protocolVersion") {
		t.Errorf("terminate mode did not complete an MCP initialize with DEFAULT settings "+
			"(E13/E14 regression):\n%s", shorten(body, 600))
	}

	// The same call through the PASSTHROUGH node. It is direct mode with the LAN
	// guard inert, so it isolates E14 from E13: it was refused identically before
	// the fix, which is what proved the rebinding guard reaches every tunnelled
	// deployment and not just the ingress.
	viaPassthrough := mcpInitialize(ctx, f, net.Name, dnsIP, "", "https://alice."+domain+"/a/alice/mcp")
	if !strings.Contains(viaPassthrough, "protocolVersion") {
		t.Errorf("a direct-mode passthrough node did not complete an MCP initialize "+
			"(E14 regression):\n%s", shorten(viaPassthrough, 600))
	}

	t.Logf("T5: passthrough kept CN=alice end to end; terminate served a verified "+
		"CA-issued certificate for bob.%s; both modes completed an MCP initialize "+
		"through the ingress at default settings", domain)
}

// chainSeen reports the certificate a caller is offered for a public name,
// resolved through the harness's own authoritative zone.
//
// curl rather than `openssl s_client`: the openssl binary is not in any image
// here, and installing it at run time made the probe depend on reaching a package
// mirror — which the first run could not, because it was pointed at a resolver
// that only knows harness.test. Verification is off on purpose; WHICH certificate
// is served is the whole question, and each caller judges it separately below.
func chainSeen(ctx context.Context, f *fabric.Fabric, network, dnsIP, name string) string {
	out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", network, "--dns", dnsIP,
		curlImage, "-sS", "-v", "-k", "-m", "20", "-o", "/dev/null", "https://"+name+"/")
	return string(out)
}

// chainVerified dials a public name with real verification against the CA root,
// which is the whole point of terminate mode: a chain a browser would accept.
func chainVerified(ctx context.Context, f *fabric.Fabric, network, dnsIP, caRoot, name string) string {
	out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", network, "--dns", dnsIP,
		"-v", caRoot+":/ca.pem:ro", curlImage,
		"-sS", "-v", "-m", "20", "--cacert", "/ca.pem", "-o", "/dev/null", "https://"+name+"/")
	return string(out)
}

// mcpInitialize sends a real MCP initialize and returns the body. A status code
// alone would not distinguish "the ingress answered" from "the node answered";
// only a protocol response can come from the node.
func mcpInitialize(ctx context.Context, f *fabric.Fabric, network, dnsIP, caRoot, url string) string {
	const req = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` +
		`"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"pact-harness","version":"1"}}}`
	args := []string{"run", "--rm", "--network", network, "--dns", dnsIP}
	verify := []string{"-k"}
	if caRoot != "" {
		args = append(args, "-v", caRoot+":/ca.pem:ro")
		verify = []string{"--cacert", "/ca.pem"}
	}
	args = append(args, curlImage, "-sS", "-m", "30", "-w", "\nHTTP %{http_code}\n")
	args = append(args, verify...)
	out, _ := f.Raw(ctx, "docker", append(args,
		"-H", "Content-Type: application/json",
		"-H", "Accept: application/json, text/event-stream",
		"-X", "POST", "--data", req, url)...)
	return string(out)
}

// waitZone blocks until the harness's own resolver answers for a name with the
// address the zone claims. busybox nslookup, so no package has to be installed —
// the resolver under test is the only one available to the container asking.
func waitZone(ctx context.Context, f *fabric.Fabric, network, dnsIP, name, want string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last string
	for {
		out, _ := f.Raw(ctx, "docker", "run", "--rm", "--network", network, alpineImage,
			"nslookup", name, dnsIP)
		last = string(out)
		if strings.Contains(last, want) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s never resolved to %s (last answer: %s)", name, want, shorten(last, 200))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// containerIP reads a container's address on its network.
func containerIP(ctx context.Context, f *fabric.Fabric, c *fabric.Container) (string, error) {
	out, err := f.Raw(ctx, "docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", c.Name)
	if err != nil {
		return "", fmt.Errorf("inspecting %s: %w", c.Name, err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("%s has no address on its network", c.Name)
	}
	return ip, nil
}

// copyFromImage lifts one file out of an image without running it — the images
// involved are distroless, so there is no shell to cat with.
func copyFromImage(ctx context.Context, f *fabric.Fabric, image, inside, dst string) error {
	out, err := f.Raw(ctx, "docker", "create", image)
	if err != nil {
		return fmt.Errorf("creating a container from %s: %w (%s)", image, err, shorten(string(out), 200))
	}
	id := strings.TrimSpace(string(out))
	defer func() { _, _ = f.Raw(context.WithoutCancel(ctx), "docker", "rm", id) }()
	if out, err := f.Raw(ctx, "docker", "cp", id+":"+inside, dst); err != nil {
		return fmt.Errorf("copying %s: %w (%s)", inside, err, shorten(string(out), 200))
	}
	return nil
}

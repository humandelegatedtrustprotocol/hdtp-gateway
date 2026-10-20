package integrationtest

// The README quickstart is the first thing a new owner does, and it was broken in
// three separate ways at once — none of which any test could see, because nothing
// compared the documented commands against what the image and compose file
// actually provide:
//
//   1. the image could not build at all (P14-03a);
//   2. `docker compose up` published no port, and the portal bound the CONTAINER's
//      loopback, so the URL it printed was unreachable even with `-p` (E12);
//   3. `docker compose exec hdtp-gateway hdtp-gateway …` — the README's own next
//      command — failed with "executable file not found in $PATH".
//
// These are the cheap structural halves. The expensive half is the harness
// standing the whole thing up and driving the wizard in a browser.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestQuickstartCommandsAreServedByTheImageAndCompose(t *testing.T) {
	root := repoRoot(t)

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}

	// (a) If the README tells the owner to exec a BARE command name, that name has
	// to resolve on the image's PATH. /hdtp-gateway alone does not.
	bareExec := regexp.MustCompile(`docker compose exec \S+ (\w[\w-]*)`)
	for _, m := range bareExec.FindAllStringSubmatch(string(readme), -1) {
		name := m[1]
		if strings.HasPrefix(name, "/") {
			continue
		}
		if !strings.Contains(string(dockerfile), "/usr/local/bin/"+name) {
			t.Errorf("README runs `docker compose exec … %s` but the image does not place "+
				"%q on PATH — the documented command fails with "+
				"\"executable file not found in $PATH\"", name, name)
		}
	}

	// (b) The README tells the owner to open the portal URL the log prints, so compose has to
	// publish it.
	if !strings.Contains(string(readme), "The log prints your portal URL") {
		t.Error("README no longer says the log prints the portal URL where this test reads it")
	}
	if !strings.Contains(string(compose), "127.0.0.1:8080:") {
		t.Error("the README tells the owner to open the portal URL, but compose publishes " +
			"nothing on host loopback — `docker compose up` prints a URL that cannot be reached")
	}

	// (c) …and only on loopback. The portal is plain HTTP in compose, which SPEC §8.3 allows on
	// loopback only; publishing "8080:8080" would put the setup wizard and the sign-in,
	// unencrypted, on the owner's whole LAN.
	if regexp.MustCompile(`(?m)^\s*-\s*"?8080:`).Match(compose) {
		t.Error("compose publishes the portal on ALL interfaces; it is plain HTTP, which SPEC §8.3 " +
			"allows on loopback only, so this would expose it to the LAN. Bind it to 127.0.0.1 only")
	}

	// (d) The limits sidecar's container inherits the image's HEALTHCHECK, which asks the node's
	// portal; this container serves none, so without a healthcheck of its own `docker compose ps`
	// listed it unhealthy for as long as it ran.
	limitdHealthcheckAsksTheSidecar(t, "compose.yaml", at(readYAML(t, filepath.Join(root, "compose.yaml")), "services", "limitd"))
}

// The node and the portal forwarder share one network, so the forwarder's 127.0.0.1 is the node's
// loopback, where the portal binds. That network is held by node-network, a container that runs a
// sleep and nothing else, and neither the node nor the forwarder owns it (#256). When the node owned
// it, `docker compose stop hdtp-gateway` and then `start` left the portal answering nothing: the
// forwarder, sharing the node's processes (#204), died with it, its one restart failed while the
// node was down ("cannot join network namespace of a non running container") and Docker did not
// try again. A container keeps the network it joined, so the holder must be the one container
// nothing has a reason to restart, and Compose restarts both joiners whenever it restarts the holder
// (`restart: true`). Measured on Docker 29.8.2 on 2026-10-20 (docs/quickstart.md § 4).
func TestTheNodesNetworkOutlivesTheNodeAndTheForwarder(t *testing.T) {
	doc := readYAML(t, filepath.Join(repoRoot(t), "compose.yaml"))
	services, _ := at(doc, "services").(map[string]any)
	holder := services["node-network"]
	if holder == nil {
		t.Fatal("compose.yaml has no node-network service holding the node's network")
	}
	for _, c := range []struct {
		key  string
		want any
		why  string
	}{
		{"image", at(services, "init-data", "image"), "the holder runs the alpine compose already pins for init-data, and no other image"},
		{"command", []any{"sleep", "infinity"}, "the holder runs nothing that can fail"},
		{"init", true, "without an init as PID 1 the sleep ignores the stop signal"},
		{"read_only", true, "the holder writes nothing"},
		{"cap_drop", []any{"ALL"}, "the holder needs no capability"},
		{"restart", "unless-stopped", "the holder comes back with Docker"},
		{"ports", []any{"127.0.0.1:8080:8081"}, "the portal is published from the network's owner, on host loopback only (SPEC §8.3)"},
	} {
		if got := at(holder, c.key); !reflect.DeepEqual(got, c.want) {
			t.Errorf("compose.yaml: node-network's %s is %v, want %v: %s", c.key, got, c.want, c.why)
		}
	}
	if aliases, _ := at(holder, "networks", "default", "aliases").([]any); !slices.Contains(aliases, any("hdtp-gateway")) {
		t.Errorf("compose.yaml: node-network's default network has aliases %v, want hdtp-gateway: ngrok, bore and a cloudflared route dial hdtp-gateway:8443", aliases)
	}
	for _, name := range []string{"hdtp-gateway", "portal"} {
		svc := services[name]
		if got := at(svc, "network_mode"); got != "service:node-network" {
			t.Errorf("compose.yaml: %s's network_mode is %v, want service:node-network: the node's portal binds the loopback of the network both share", name, got)
		}
		if got := at(svc, "ports"); got != nil {
			t.Errorf("compose.yaml: %s publishes %v; a container that joins another's network publishes nothing, node-network publishes the portal", name, got)
		}
		if got := at(svc, "restart"); got != "unless-stopped" {
			t.Errorf("compose.yaml: %s's restart is %v, want unless-stopped: after a crash its restart policy brings it back into node-network's network", name, got)
		}
		if got := at(svc, "depends_on", "node-network", "restart"); got != true {
			t.Errorf("compose.yaml: %s's depends_on.node-network.restart is %v, want true: after node-network restarts, a container that kept the old network answers nothing until it is restarted too", name, got)
		}
	}
	if got, _ := at(services, "portal", "cap_drop").([]any); !reflect.DeepEqual(got, []any{"ALL"}) {
		t.Errorf("compose.yaml: the portal's cap_drop is %v, want [ALL]: it shares the node's network and needs no capability", got)
	}
	// Nothing joins the node's own namespaces: a container that did would be stranded by every stop
	// of the node, which is #256.
	for name, svc := range services {
		for _, key := range []string{"network_mode", "pid", "ipc"} {
			if got := at(svc, key); got == "service:hdtp-gateway" {
				t.Errorf("compose.yaml: %s's %s is service:hdtp-gateway; a stop of the node strands it (#256)", name, key)
			}
		}
	}
}

// limitdHealthcheckAsksTheSidecar holds a compose file's `limitd` service to the healthcheck that
// asks the sidecar itself (`hdtp-gateway healthcheck --limits`, internal/cli/healthcheck.go), run
// with the binary the image has: distroless has no shell.
func limitdHealthcheckAsksTheSidecar(t *testing.T, file string, limitd any) {
	t.Helper()
	if limitd == nil {
		t.Fatalf("%s has no limitd service", file)
	}
	test, _ := at(limitd, "healthcheck", "test").([]any)
	want := []any{"CMD", "/hdtp-gateway", "healthcheck", "--limits"}
	if !reflect.DeepEqual(test, want) {
		t.Errorf("%s: the limitd service's healthcheck is %v; the image's asks the portal, which this "+
			"container does not serve, so it must be %v", file, test, want)
	}
}

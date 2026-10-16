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

// The portal forwarder shares the node's network (network_mode service:hdtp-gateway), and after
// `docker compose restart hdtp-gateway` it answered nothing until it was restarted too (#169). `restart: true` under its depends_on entry asks
// Compose to restart it whenever Compose restarts the node (`docker compose restart hdtp-gateway`).
// Whether Compose does the same after the runtime restarts a node that crashed is not measured here.
func TestThePortalForwarderRestartsWithTheNode(t *testing.T) {
	root := repoRoot(t)
	dep := at(readYAML(t, filepath.Join(root, "compose.yaml")), "services", "portal", "depends_on", "hdtp-gateway")
	if dep == nil {
		t.Fatal("compose.yaml: the portal service does not depend on hdtp-gateway")
	}
	if got := at(dep, "restart"); got != true {
		t.Errorf("compose.yaml: the portal's depends_on.hdtp-gateway.restart is %v, want true: "+
			"after `docker compose restart hdtp-gateway` the forwarder answers nothing until it is restarted too", got)
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

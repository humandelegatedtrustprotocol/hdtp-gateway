package cli

// The owner's rule of 2026-09-29 (docs/release/two-layer-limits-2026-09-28.md §6), as an operator
// meets it: while the limits sidecar does not answer, the node's health check fails and says why,
// `doctor` names it, and the serve banner says so; once it answers again, all three are well, with
// no restart of the node.

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits/limitstest"
)

func TestASidecarThatIsDownIsNamedByTheHealthCheckDoctorAndTheBanner(t *testing.T) {
	side := limitstest.StartDefault(t)
	t.Setenv("HDTP_LIMITS_SOCKET", side.Path)
	r := runServe(t, nil)
	cfg := filepath.Join(r.dir, "config.json")
	health := func() (int, string) {
		t.Helper()
		res, err := http.Get("http://" + r.internal + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	doctorSays := func() string {
		var out, errOut bytes.Buffer
		doctor([]string{"--config", cfg}, &out, &errOut)
		return out.String()
	}

	// The control: answering, all three say so.
	if code, body := health(); code != 200 || body != "ok\n" {
		t.Fatalf("healthz with the sidecar answering: %d %q", code, body)
	}
	if out := doctorSays(); !strings.Contains(out, "ok   limits       "+side.Path+" answering") {
		t.Fatalf("doctor with the sidecar answering:\n%s", out)
	}
	if !strings.Contains(r.out.String(), "limits:  "+side.Path+" answering") {
		t.Fatalf("the banner does not say the sidecar answers:\n%s", r.out.String())
	}

	side.Stop()
	if code, body := health(); code != http.StatusServiceUnavailable || !strings.Contains(body, side.Path) || !strings.Contains(body, "refused unavailable") {
		t.Fatalf("healthz with the sidecar down: %d %q, want 503 naming it and what it means", code, body)
	}
	var errOut bytes.Buffer
	if code := healthcheck([]string{"--config", cfg}, &errOut); code == 0 {
		t.Fatal("the container healthcheck passed with the sidecar down")
	}
	if out := doctorSays(); !strings.Contains(out, "FAIL limits       "+side.Path) || !strings.Contains(out, "every sealed call is refused unavailable") {
		t.Fatalf("doctor with the sidecar down:\n%s", out)
	}

	side.Restart(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _ := health()
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the node did not see its sidecar come back without a restart")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The sidecar's own container serves no portal (compose.yaml's `limitd`), so its healthcheck asks
// the sidecar over the socket the node asks it on, and nothing else: with no portal listening it
// passes while the sidecar answers and fails, naming the socket, once it does not.
func TestTheHealthcheckOfTheSidecarAsksItsSocketAndNoPortal(t *testing.T) {
	side := limitstest.StartDefault(t)
	t.Setenv("HDTP_LIMITS_SOCKET", side.Path)
	t.Setenv("HDTP_INTERNAL_BIND", freePort(t))
	var stderr bytes.Buffer
	if code := healthcheck([]string{"--limits"}, &stderr); code != 0 {
		t.Fatalf("the sidecar answers and its healthcheck exited %d: %s", code, stderr.String())
	}
	side.Stop()
	stderr.Reset()
	if code := healthcheck([]string{"--limits"}, &stderr); code == 0 || !strings.Contains(stderr.String(), side.Path) {
		t.Fatalf("the sidecar is down and its healthcheck exited %d saying %q; it fails and names the socket", code, stderr.String())
	}
}

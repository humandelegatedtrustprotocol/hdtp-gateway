package public

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// AC (P8-01, defect #5): the guard must decide per request. It once evaluated
// its own irrelevance when the handler was wired, so an owner flipping the flag
// at runtime changed nothing until the process restarted.
func TestLANGuardDecidesPerRequestNotAtWiringTime(t *testing.T) {
	allow := true
	var refusals int
	g := LANGuard{
		Adapter: "frp", // an active adapter makes the flag meaningful
		AllowFn: func() bool { return allow },
		Audit:   func(string, string, string) { refusals++ },
	}
	served := 0
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))
	call := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/a/me/mcp", nil)
		req.RemoteAddr = "10.0.0.7:1234" // private range
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(); code != http.StatusOK {
		t.Fatalf("LAN allowed, got %d", code)
	}
	allow = false
	if code := call(); code != http.StatusForbidden {
		t.Fatalf("after turning the LAN flag off the SAME handler still served: %d", code)
	}
	if refusals != 1 {
		t.Fatalf("the refusal was not audited: %d rows", refusals)
	}
	allow = true
	if code := call(); code != http.StatusOK {
		t.Fatalf("turning the flag back on did not restore service: %d", code)
	}
	if served != 2 {
		t.Fatalf("served %d times, want 2", served)
	}
}

// E13. A reverse-tunnel connector delivers from LOOPBACK: it runs on the node's
// own host — in-process for frp, ngrok and tsnet, a child process for cloudflared
// — and dials the node's public bind. The flag governs connections that BYPASS
// the configured carrier (SPEC §3, §10.1); the carrier's own delivery is not a
// bypass, and no LAN host can present a loopback source, because the kernel drops
// 127/8 arriving on an external interface.
//
// While loopback was refused, EVERY edge-mode deployment refused its own
// connector's traffic and could not serve a single request — cloudflare and ngrok
// as much as ingress-terminate, since edge mode is what defaults the flag off.
//
// Loopback grants no authority here: the caller is still a guest unless it
// presents a client certificate or a sealed envelope. That is why this is safe
// while §8.4 refuses to treat loopback as authority for the owner MCP, where it
// WOULD grant everything.
func TestLANGuardServesTheCarriersOwnLoopbackDelivery(t *testing.T) {
	var refusals int
	g := LANGuard{
		Adapter: "cloudflare", // an edge adapter: the flag is off and meaningful
		Allow:   false,
		Audit:   func(string, string, string) { refusals++ },
	}
	served := 0
	h := g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))
	call := func(remote string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/a/me/mcp", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for _, remote := range []string{"127.0.0.1:52001", "[::1]:52002"} {
		if code := call(remote); code != http.StatusOK {
			t.Errorf("a connector delivering from %s was refused (%d); no edge-mode "+
				"deployment can serve a request while this is true", remote, code)
		}
	}
	// Everything else in the private list is still a bypass and still refused.
	for _, remote := range []string{"10.0.0.7:1234", "192.168.1.5:1234", "172.16.3.9:1234"} {
		if code := call(remote); code != http.StatusForbidden {
			t.Errorf("a LAN source %s was served (%d); the guard has been widened past "+
				"the carrier's own delivery", remote, code)
		}
	}
	if refusals != 3 {
		t.Errorf("audited %d refusals, want 3 — every refusal must be audited (SPEC §11)", refusals)
	}
}

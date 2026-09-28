package node

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/public"
)

// On the shipped listener, over TLS, behind a terminating edge (the source address from its
// trusted header, SPEC §5.7): a source past its request bucket is answered 429 `rate_limited` by
// the outermost handler — before the body cap reads the body (a 9 MiB body gets 429 from it, and
// 413 `too_large` from an address with budget left), and so before the transport facts and the
// client chain inside it — and another source, sent last, is served.
func TestTheListenerRefusesAFloodBeforeTheBodyCapAndServesAnotherSource(t *testing.T) {
	e, _ := newEnv(t, "alice")
	e.cfg.Mode = core.ModeEdge
	o := e.options()
	o.Config = e.cfg
	o.Adapter = "cloudflare"
	o.Flood = &public.FloodLimits{MaxConns: 64, Conns: public.Rate{PerSecond: 100, Burst: 100}, IPConns: public.Rate{PerSecond: 100, Burst: 100},
		Requests: public.Rate{PerSecond: 100, Burst: 100}, IPRequests: public.Rate{PerSecond: 0.001, Burst: 3}}
	_, base := e.start(o)

	post := func(src string, body []byte) (int, string) {
		t.Helper()
		req, err := http.NewRequest("POST", base+"/a/alice/mcp", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("CF-Connecting-IP", src)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := insecureClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	list := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	huge := bytes.Repeat([]byte("x"), MaxBodyBytes+1<<20)

	if code, body := post("203.0.113.9", huge); code != http.StatusRequestEntityTooLarge || !strings.Contains(body, "too_large") {
		t.Fatalf("an oversized body from a source with budget: %d %s", code, body)
	}
	for i := 0; i < 2; i++ {
		if code, _ := post("203.0.113.9", list); code != http.StatusOK {
			t.Fatalf("request %d within the source's burst: %d", i, code)
		}
	}
	for i := 0; i < 5; i++ {
		if code, body := post("203.0.113.9", list); code != http.StatusTooManyRequests || !strings.Contains(body, `"rate_limited"`) {
			t.Fatalf("flood request %d: %d %s", i, code, body)
		}
	}
	if code, body := post("203.0.113.9", huge); code != http.StatusTooManyRequests {
		t.Fatalf("an oversized body past the source's budget got %d (%s): the body cap ran before the flood limit", code, body)
	}
	// The control.
	if code, body := post("198.51.100.7", list); code != http.StatusOK || !strings.Contains(body, "request_contact") {
		t.Fatalf("another source was refused after the flood: %d %s", code, body)
	}
}

package integrationtest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
)

// wireHints is one tool's four hints as a listing carries them, in the fixture's spelling.
type wireHints struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

// servedProtocolHints is what this node's HDTP surface says of each tool on the wire, read from
// `tools/list` through the go-sdk Streamable HTTP handler in the mode the node serves it
// (stateless, JSON), for a guest, a pending contact and a contact granted every core permission:
// between them every HDTP tool is served once, `sealed_call` on each tier.
func servedProtocolHints(t *testing.T) map[string]wireHints {
	t.Helper()
	tiers := map[string]policy.Tier{"sha256:asked": policy.TierPending, "sha256:alina": policy.TierContact}
	perms := map[string]bool{"message.text": true, "message.media": true, "status.view": true,
		"calendar.availability": true, "calendar.book": true}
	resolve := func(_ context.Context, accountID, fpr string) (policy.Caller, error) {
		tier, ok := tiers[fpr]
		if !ok {
			tier = policy.TierGuest
		}
		c := policy.Caller{AccountID: accountID, Fingerprint: fpr, Tier: tier}
		if tier == policy.TierContact {
			c.Permissions = perms
		}
		return c, nil
	}
	reg := &public.Registry{}
	reg.Add(public.BuiltinEntries(public.ToolDeps{})...)
	reg.Add(public.SealedEntries(public.SealedDeps{})...)
	pool := public.NewPool(reg, resolve, 8)

	out := map[string]wireHints{}
	for _, fpr := range []string{"", "sha256:asked", "sha256:alina"} {
		srv, err := pool.ServerFor(context.Background(), "acct", fpr)
		if err != nil {
			t.Fatal(err)
		}
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
			&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("tools/list for %q: %d %s", fpr, rec.Code, rec.Body.String())
		}
		var env struct {
			Result struct {
				Tools []struct {
					Name        string                     `json:"name"`
					Annotations map[string]json.RawMessage `json:"annotations"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("tools/list for %q does not decode: %v\n%s", fpr, err, rec.Body.String())
		}
		for _, tl := range env.Result.Tools {
			if len(tl.Annotations) != 4 {
				t.Fatalf("%s carries %d annotation keys on the wire, want the four hints", tl.Name, len(tl.Annotations))
			}
			raw, _ := json.Marshal(tl.Annotations)
			var h wireHints
			if err := json.Unmarshal(raw, &h); err != nil {
				t.Fatalf("%s: a hint is not a boolean: %v\n%s", tl.Name, err, raw)
			}
			out[tl.Name] = h
		}
	}
	return out
}

// The cloud holds its own HDTP surface to this node's hints: BatonDeck's vitest reads
// `gateway/test/fixtures/go-protocol-tools.json` and its conformance battery asks a node for the
// same. The fixture is the node's hints as somebody wrote them down, so it is checked here against
// what this node serves, as the owner-tools fixture is. When it differs, the fixture is what moves;
// the cloud's own test then says what the cloud owes.
func TestTheCloudsCopyOfTheProtocolHintsIsCurrent(t *testing.T) {
	root := repoRoot(t)
	fixture := filepath.Join(root, "..", "batondeck", "gateway", "test", "fixtures", "go-protocol-tools.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("SKIPPED, and so the cloud's copy is unchecked: no batondeck beside this repo (%v)", err)
	}
	var doc struct {
		Tools map[string]wireHints `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", fixture, err)
	}

	served := servedProtocolHints(t)
	if len(served) < 14 {
		t.Fatalf("read only %d served tools: the reader is broken, not the fixture", len(served))
	}
	names := func(m map[string]wireHints) []string {
		out := make([]string, 0, len(m))
		for n := range m {
			out = append(out, n)
		}
		sort.Strings(out)
		return out
	}
	if got, want := names(doc.Tools), names(served); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("batondeck/gateway/test/fixtures/go-protocol-tools.json does not name this node's HDTP tools.\n  the fixture: %v\n  this node:   %v", got, want)
	}
	for name, want := range served {
		if got := doc.Tools[name]; got != want {
			t.Errorf("%s: the fixture says %+v, this node serves %+v", name, got, want)
		}
	}
	if t.Failed() {
		t.Log("Change the fixture to match, and then the cloud's own test will say what the cloud owes.")
	}
}

package providers

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// E15. MCP does not require text content to be JSON, and answering with a bare
// identifier is ordinary: caldav-mcp's `create-event` — the tool a `book_slot`
// binding uses — returns the event's uid and nothing else. Rejecting that made a
// spec-legal server impossible to bind at all, and reported the fault as if the
// SERVER were malformed.
func TestPlainTextResultIsAValueNotAnError(t *testing.T) {
	const uid = "0f9c1b1e-6c2a-4f77-9a10-2b0d1f3e5a44"
	got, err := decodeResult("create-event", textResult(uid))
	if err != nil {
		t.Fatalf("a plain identifier was rejected, so book_slot cannot bind: %v", err)
	}
	// An empty Out path resolves it through Lookup, so the DSL stays field paths
	// and constants with no new form (SPEC §6.7).
	s, ok := integrations.LookupString(got, "")
	if !ok || s != uid {
		t.Fatalf("Out path \"\" did not resolve the identifier: %#v", got)
	}
}

// An identifier that happens to be all digits is still an identifier. Parsing it
// as JSON would make it a number, and every Out path expecting a string would
// then miss — a failure that would only appear for some upstreams, some of the
// time, which is the worst kind.
func TestNumericLookingIdentifierStaysAString(t *testing.T) {
	got, err := decodeResult("create-event", textResult("20260826"))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := integrations.LookupString(got, ""); !ok || s != "20260826" {
		t.Fatalf("a digit-only identifier was decoded as %#v", got)
	}
}

// Structured shapes must still decode, or every existing recipe breaks.
func TestJSONObjectsAndArraysStillDecode(t *testing.T) {
	got, err := decodeResult("get-freebusy", textResult(`{"calendars":{"primary":{"busy":[]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := integrations.Lookup(got, "calendars.primary.busy"); !ok {
		t.Fatalf("an object result no longer walks its Out path: %#v", got)
	}
	// list-events returns a top-level ARRAY, which `out.busy: ""` resolves.
	got, err = decodeResult("list-events", textResult(`[{"start":"a","end":"b"}]`))
	if err != nil {
		t.Fatal(err)
	}
	list, ok := integrations.Lookup(got, "")
	if !ok {
		t.Fatal("an array result did not resolve through the empty path")
	}
	if _, ok := list.([]any); !ok {
		t.Fatalf("array decoded as %T", list)
	}
}

// Structured content still wins over text when the upstream provides it.
func TestStructuredContentWins(t *testing.T) {
	res := textResult(`"ignored"`)
	res.StructuredContent = map[string]any{"id": "abc"}
	got, err := decodeResult("create-event", res)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := integrations.LookupString(got, "id"); s != "abc" {
		t.Fatalf("structured content was not preferred: %#v", got)
	}
}

// Upstream output is untrusted input (SPEC §6.10). Accepting text as a value
// makes an unbounded response a memory question, so it is capped here.
func TestOversizeUpstreamTextIsRefused(t *testing.T) {
	_, err := decodeResult("list-events", textResult(strings.Repeat("x", MaxUpstreamText+1)))
	if err == nil {
		t.Fatal("an unbounded upstream response was accepted")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error does not say what the limit is: %v", err)
	}
	if _, err := decodeResult("list-events", textResult(strings.Repeat("x", MaxUpstreamText))); err != nil {
		t.Errorf("a response exactly at the cap was refused: %v", err)
	}
}

func TestUpstreamToolErrorSurfaces(t *testing.T) {
	res := textResult(`{}`)
	res.IsError = true
	if _, err := decodeResult("create-event", res); err == nil {
		t.Fatal("an upstream tool error was reported as success")
	}
}

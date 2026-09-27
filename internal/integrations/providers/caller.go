package providers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/integrations"
)

// ManagerCaller binds a provider to a live upstream session: the tool result's
// structured content, else its first text content parsed as JSON, becomes the
// decoded value the recipe's Out paths walk. Outages surface as errors so the
// serving layer answers `unavailable` (SPEC §6.10).
func ManagerCaller(m *integrations.Manager, integrationID string) Caller {
	return func(ctx context.Context, tool string, args map[string]any) (any, error) {
		if !m.Available(integrationID) {
			return nil, fmt.Errorf("providers: upstream unavailable")
		}
		cs := m.Session(integrationID)
		if cs == nil {
			return nil, fmt.Errorf("providers: upstream unavailable")
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			// Tell the manager what this call learned: a server that handshakes
			// without a credential and refuses the real work would otherwise
			// leave the row green forever.
			m.NoteCallFailure(ctx, integrationID, err)
			return nil, fmt.Errorf("providers: upstream unavailable: %w", err)
		}
		return decodeResult(tool, res)
	}
}

// MaxUpstreamText caps the text a recipe will consume from an upstream server.
// That output is untrusted input (SPEC §6.10), and once plain text is a VALUE
// rather than an error an unbounded response becomes a memory question.
const MaxUpstreamText = 256 << 10

// decodeResult turns a tool result into the value a recipe's Out paths walk.
//
// Split out of the closure so it can be tested without a live upstream session:
// the rule it encodes was wrong for a year and there was nothing to point a test
// at.
func decodeResult(tool string, res *mcp.CallToolResult) (any, error) {
	if res.IsError {
		return nil, fmt.Errorf("providers: upstream tool %s failed", tool)
	}
	if res.StructuredContent != nil {
		return res.StructuredContent, nil
	}
	for _, c := range res.Content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			continue
		}
		if len(tc.Text) > MaxUpstreamText {
			return nil, fmt.Errorf("providers: upstream %s returned %d bytes of text, over the %d cap",
				tool, len(tc.Text), MaxUpstreamText)
		}
		// Only an OBJECT or ARRAY is structure a dot path can walk. Anything else
		// is an identifier or a message, and stays the string it is — which an
		// empty Out path resolves through Lookup, so the DSL keeps to field paths
		// and constants with no new form (SPEC §6.7).
		//
		// Rejecting non-JSON text made spec-legal servers impossible to bind: MCP
		// never required text content to be JSON, and answering with a bare id is
		// ordinary — caldav-mcp's create-event returns the event uid and nothing
		// else. Parsing scalars would be just as wrong in the other direction: a
		// digit-only identifier would silently become a number and every Out path
		// expecting a string would miss.
		var v any
		if err := json.Unmarshal([]byte(tc.Text), &v); err == nil {
			switch v.(type) {
			case map[string]any, []any:
				return v, nil
			}
		}
		return tc.Text, nil
	}
	return map[string]any{}, nil
}

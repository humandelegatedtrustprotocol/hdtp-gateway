package integrations

// Passthrough serving mode (SPEC §6.6): validate the caller's arguments against
// the SNAPSHOTTED inputSchema — the SDK's low-level server path does not
// validate, and a live upstream schema must never widen what was confirmed —
// then forward under the upstream tool name and relay the result as data.
// Invalid arguments fail `bad_request` without touching the upstream; transport
// failures and outages surface as `unavailable`; oversized results are
// truncated WITH a `too_large` error, never silently.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// DefaultCallTimeout bounds one upstream forward.
	DefaultCallTimeout = 30 * time.Second
	// DefaultMaxResultBytes caps the relayed result payload: comfortably under
	// the caller-side 8 MiB request cap (SPEC §5.7), deliberately small — an
	// upstream answering a contact should not need more than 1 MiB.
	DefaultMaxResultBytes = 1 << 20
)

// Passthrough forwards exposed tools to their upstream (SPEC §6.6). Zero
// Timeout and MaxResultBytes select DefaultCallTimeout and DefaultMaxResultBytes.
type Passthrough struct {
	// Manager supplies the live upstream session and its availability.
	Manager *Manager
	// Timeout bounds one forward; 0 = DefaultCallTimeout.
	Timeout time.Duration
	// MaxResultBytes caps the relayed result; 0 = DefaultMaxResultBytes.
	MaxResultBytes int
	// Audit receives passthrough_call rows for arguments that fail the snapshot's schema
	// (bad_request), an upstream call that errors (unavailable) and a result over the cap
	// (too_large); nil discards. Not audited here: arguments that are not JSON, an integration
	// that is not available, a missing session, and successful forwards.
	Audit func(action, resource, outcome string)
}

func (p *Passthrough) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return DefaultCallTimeout
}

func (p *Passthrough) maxBytes() int {
	if p.MaxResultBytes > 0 {
		return p.MaxResultBytes
	}
	return DefaultMaxResultBytes
}

func (p *Passthrough) audit(action, resource, outcome string) {
	if p.Audit != nil {
		p.Audit(action, resource, outcome)
	}
}

func errResult(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + code + `"}`}},
	}
}

// Handler compiles the snapshotted schema once and returns the serving handler
// for one exposed passthrough entry. def MUST come from the catalog snapshot
// the exposure was confirmed on — never from a live ListTools.
//
// accountID is what this entry's audit rows are attributed to: the trail's
// account column scopes a narrowed token's reads (SPEC §11.6) and the portal's
// audit page, and an unattributed row is readable by every owner on the node.
func (p *Passthrough) Handler(accountID, integrationID string, def ToolDef) (mcp.ToolHandler, error) {
	var schema *jsonschema.Schema
	if len(def.InputSchema) > 0 && string(def.InputSchema) != "null" {
		schema = new(jsonschema.Schema)
		if err := json.Unmarshal(def.InputSchema, schema); err != nil {
			return nil, fmt.Errorf("integrations: snapshot schema for %s: %w", def.Name, err)
		}
	}
	var resolved *jsonschema.Resolved
	if schema != nil {
		r, err := schema.Resolve(nil)
		if err != nil {
			return nil, fmt.Errorf("integrations: resolve schema for %s: %w", def.Name, err)
		}
		resolved = r
	}
	upstreamTool := def.Name // forwarded under the SNAPSHOT's name
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// arguments validate against the confirmed snapshot, or the call never leaves
		if resolved != nil {
			var instance any
			raw := req.Params.Arguments
			if len(raw) == 0 {
				raw = json.RawMessage(`{}`)
			}
			if err := json.Unmarshal(raw, &instance); err != nil {
				return errResult("bad_request"), nil
			}
			if err := resolved.Validate(instance); err != nil {
				p.audit("passthrough_call", "account:"+accountID+" tool:"+upstreamTool, "bad_request")
				return errResult("bad_request"), nil
			}
		}
		if !p.Manager.Available(integrationID) {
			return errResult("unavailable"), nil
		}
		cs := p.Manager.Session(integrationID)
		if cs == nil {
			return errResult("unavailable"), nil
		}
		callCtx, cancel := context.WithTimeout(ctx, p.timeout())
		defer cancel()
		res, err := cs.CallTool(callCtx, &mcp.CallToolParams{
			Name: upstreamTool, Arguments: req.Params.Arguments,
		})
		if err != nil {
			// transport failure (timeout included) — never a schema problem
			p.audit("passthrough_call", "account:"+accountID+" tool:"+upstreamTool, "unavailable")
			return errResult("unavailable"), nil
		}
		if capped, over := p.capResult(res); over {
			p.audit("passthrough_call", "account:"+accountID+" tool:"+upstreamTool, "too_large")
			return capped, nil
		}
		// upstream tool errors relay as tool errors; results relay as data
		return res, nil
	}, nil
}

// capResult enforces the relay size cap: an oversized result is truncated AND
// marked as an error so the caller can never mistake it for complete data.
func (p *Passthrough) capResult(res *mcp.CallToolResult) (*mcp.CallToolResult, bool) {
	total := 0
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			total += len(tc.Text)
		} else if b, err := json.Marshal(c); err == nil {
			total += len(b)
		}
	}
	if total <= p.maxBytes() {
		return res, false
	}
	preview := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			cut := p.maxBytes()
			if cut > len(tc.Text) {
				cut = len(tc.Text)
			}
			preview = tc.Text[:cut]
		}
	}
	head, _ := json.Marshal(map[string]any{
		"code": "too_large", "truncated": true, "limit_bytes": p.maxBytes(),
	})
	out := &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: string(head)}}}
	if preview != "" {
		out.Content = append(out.Content, &mcp.TextContent{Text: preview})
	}
	return out, true
}

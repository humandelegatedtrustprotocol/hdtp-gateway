// Package owner drives a node's owner MCP — the surface an owner's own agent
// uses (SPEC §8.4).
//
// It is a plain MCP client over Streamable HTTP with a bearer token, because that
// is exactly what the product serves. The one wrinkle is reach: the internal
// surface binds loopback INSIDE the container (§8.3 refuses a non-loopback bind
// without auth and TLS), so a scenario reaches it through a sidecar sharing the
// node's network namespace rather than by weakening the node.
package owner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Client is a connected owner-MCP session.
type Client struct {
	sess *mcp.ClientSession
}

// bearer adds the owner token to every request. The owner MCP requires a named,
// revocable token on EVERY bind, loopback included (SPEC §8.4).
type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// Connect opens an owner-MCP session against endpoint.
func Connect(ctx context.Context, endpoint, token string) (*Client, error) {
	hc := &http.Client{
		Timeout:   60 * time.Second,
		Transport: bearer{token: token, base: http.DefaultTransport},
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "harness-owner", Version: "1"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: hc}, nil)
	if err != nil {
		return nil, fmt.Errorf("owner: connecting to %s: %w", endpoint, err)
	}
	return &Client{sess: sess}, nil
}

func (c *Client) Close() error { return c.sess.Close() }

// Tools lists the owner surface.
func (c *Client) Tools(ctx context.Context) ([]string, error) {
	list, err := c.sess.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("owner: listing tools: %w", err)
	}
	var names []string
	for _, t := range list.Tools {
		names = append(names, t.Name)
	}
	return names, nil
}

// ToolArgs is every tool's argument names, read from the input schema the server publishes: what
// a scenario enumerates when a rule holds for every tool that takes a given argument.
func (c *Client) ToolArgs(ctx context.Context) (map[string][]string, error) {
	list, err := c.sess.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("owner: listing tools: %w", err)
	}
	out := map[string][]string{}
	for _, t := range list.Tools {
		raw, err := json.Marshal(t.InputSchema)
		if err != nil {
			return nil, err
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		_ = json.Unmarshal(raw, &schema)
		names := []string{}
		for k := range schema.Properties {
			names = append(names, k)
		}
		out[t.Name] = names
	}
	return out, nil
}

// Call invokes one owner tool and returns its text content.
//
// A tool that answers with isError is returning an ANSWER, not failing at the
// transport — surfacing it as an error keeps a refusal from reading as success.
func (c *Client) Call(ctx context.Context, tool string, args map[string]any) (string, error) {
	res, err := c.sess.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", fmt.Errorf("owner: calling %s: %w", tool, err)
	}
	text := ""
	for _, ct := range res.Content {
		if tc, ok := ct.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if res.IsError {
		return text, fmt.Errorf("owner: %s refused: %s", tool, text)
	}
	return text, nil
}

// CallJSON invokes a tool and decodes its text content as JSON.
func (c *Client) CallJSON(ctx context.Context, tool string, args map[string]any, out any) error {
	text, err := c.Call(ctx, tool, args)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(text), out); err != nil {
		return fmt.Errorf("owner: %s returned unparseable JSON %q: %w", tool, text, err)
	}
	return nil
}

// Accounts returns the account ids this owner administers (SPEC §3.3).
func (c *Client) Accounts(ctx context.Context) ([]string, error) {
	var ids []string
	if err := c.CallJSON(ctx, "list_accounts", map[string]any{}, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

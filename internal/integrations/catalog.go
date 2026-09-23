package integrations

// Catalog snapshots (SPEC §6.4): the node never serves live upstream state.
// Every successful connect, list_changed notification, health cycle, and manual
// refresh walks the upstream's tools and — only when the set or any per-tool
// content hash changed — mints an immutable snapshot vN. The hash covers
// name + description + inputSchema in canonical key-sorted JSON; annotations
// are captured for the UI but excluded (untrusted hints, SPEC §6.9).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
)

type mcpListToolsParams = mcp.ListToolsParams

// ToolDef is one snapshotted tool definition.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
	Hash        string          `json:"hash"`
}

// canonicalJSON re-marshals arbitrary JSON with lexicographically sorted keys
// at every level (Go's map marshaling sorts keys).
func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("null"), nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("integrations: %w", err)
	}
	return json.Marshal(v)
}

// HashTool computes the SPEC §6.4 content hash over (name, description,
// inputSchema) in canonical form.
func HashTool(name, description string, inputSchema json.RawMessage) (string, error) {
	schema, err := canonicalJSON(inputSchema)
	if err != nil {
		return "", err
	}
	row, err := json.Marshal(map[string]any{
		"description": description,
		"inputSchema": json.RawMessage(schema),
		"name":        name,
	})
	if err != nil {
		return "", fmt.Errorf("integrations: %w", err)
	}
	sum := sha256.Sum256(row)
	return hex.EncodeToString(sum[:]), nil
}

// Snapshot walks the connected upstream's tools and returns hashed definitions,
// sorted by name for deterministic storage.
func (m *Manager) Snapshot(ctx context.Context, integrationID string) ([]ToolDef, error) {
	cs := m.Session(integrationID)
	if cs == nil {
		return nil, fmt.Errorf("integrations: %s is not connected", nameOf(ctx, m.Store, integrationID))
	}
	var defs []ToolDef
	var cursor string
	for {
		res, err := cs.ListTools(ctx, &mcpListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("integrations: list tools: %w", err)
		}
		for _, t := range res.Tools {
			schema, err := json.Marshal(t.InputSchema)
			if err != nil {
				return nil, fmt.Errorf("integrations: %w", err)
			}
			var ann json.RawMessage
			if t.Annotations != nil {
				ann, _ = json.Marshal(t.Annotations)
			}
			h, err := HashTool(t.Name, t.Description, schema)
			if err != nil {
				return nil, err
			}
			defs = append(defs, ToolDef{
				Name: t.Name, Description: t.Description,
				InputSchema: schema, Annotations: ann, Hash: h,
			})
		}
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs, nil
}

// Cataloger persists snapshots and reports diffs.
type Cataloger struct {
	Store   store.Store
	Manager *Manager
	Audit   func(action, resource, outcome string)
	// OnMinted fires after a NEW snapshot version lands — the stale guard
	// (Exposures.Reconcile) hangs off this (SPEC §6.5).
	OnMinted func(integrationID string)
}

func (c *Cataloger) audit(action, resource, outcome string) {
	if c.Audit != nil {
		c.Audit(action, resource, outcome)
	}
}

// Refresh snapshots the upstream and mints a new version ONLY when the tool set
// or any hash changed. Returns the current catalog and whether it is new.
func (c *Cataloger) Refresh(ctx context.Context, integrationID string) (store.Catalog, bool, error) {
	in, err := c.Store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return store.Catalog{}, false, err
	}
	defs, err := c.Manager.Snapshot(ctx, integrationID)
	if err != nil {
		c.audit("catalog_refresh", "account:"+in.AccountID+" integration:"+in.Slug, "error")
		return store.Catalog{}, false, err
	}
	toolsJSON, err := json.Marshal(defs)
	if err != nil {
		return store.Catalog{}, false, fmt.Errorf("integrations: %w", err)
	}
	latest, err := c.Store.LatestCatalog(ctx, integrationID)
	if err == nil && sameToolSet(latest.Tools, defs) {
		return latest, false, nil
	}
	version := int64(1)
	if err == nil {
		version = latest.Version + 1
	}
	cat, err := c.Store.InsertCatalog(ctx, store.Catalog{
		IntegrationID: integrationID, Version: version, Tools: string(toolsJSON),
	})
	if err != nil {
		return store.Catalog{}, false, err
	}
	c.audit("catalog_snapshot", fmt.Sprintf("account:"+in.AccountID+" integration:%s:v%d", in.Slug, version), "ok")
	if c.OnMinted != nil {
		c.OnMinted(integrationID)
	}
	return cat, true, nil
}

// sameToolSet compares by name→hash only: annotation drift never mints (§6.4).
func sameToolSet(storedJSON string, defs []ToolDef) bool {
	var stored []ToolDef
	if err := json.Unmarshal([]byte(storedJSON), &stored); err != nil {
		return false
	}
	if len(stored) != len(defs) {
		return false
	}
	prev := make(map[string]string, len(stored))
	for _, t := range stored {
		prev[t.Name] = t.Hash
	}
	for _, t := range defs {
		if prev[t.Name] != t.Hash {
			return false
		}
	}
	return true
}

// nameOf names an integration the way its owner knows it — by slug — for any
// message a person will read. The id is a database key, not a name.
func nameOf(ctx context.Context, st store.Store, integrationID string) string {
	if st != nil {
		if in, err := st.GetIntegrationByID(ctx, integrationID); err == nil && in.Slug != "" {
			return in.Slug
		}
	}
	return integrationID
}

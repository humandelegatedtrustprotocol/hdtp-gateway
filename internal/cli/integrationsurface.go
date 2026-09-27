package cli

// Projecting an exposure set onto the served surface (SPEC §6.5, §6.6).
//
// The pieces all existed and none of them met: `Exposures.ActiveEntries` had no
// caller, `Passthrough.Handler` appeared zero times outside tests, and the
// registry could not be revised. So the exposure picker wrote a row and no
// contact ever gained a tool — §6's entire serving half.
//
// Two rules from §6 shape this and neither is a detail:
//
//   - nothing an upstream offers is exposed by default. Only entries in the
//     published set, and only ones the stale guard has not withdrawn, are built;
//   - passthrough and agent-answered capabilities are gated by the per-integration
//     permission `integration.<slug>`. Mapped mode is the exception: it serves
//     PACT's own vocabulary and is gated by the matching core permission, which
//     is why mapped entries are NOT projected here (§6.6, P10-04e).

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pact-cloud/pact-gateway/internal/core/policy"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/integrations"
	"github.com/pact-cloud/pact-gateway/internal/node"
	"github.com/pact-cloud/pact-gateway/internal/public"
	"github.com/pact-cloud/pact-gateway/internal/services/integrationchain"
)

// integrationSurface rebuilds what one integration serves.
type integrationSurface struct {
	store   store.Store
	chain   *integrationchain.Chain
	pass    *integrations.Passthrough
	node    *node.Node
	auditFn func(action, resource, outcome string)
	agent   *integrations.AgentAnswered
}

// rebuild1 is rebuild with the ambient context, for use as a change hook.
func (s *integrationSurface) rebuild1(integrationID string) {
	s.rebuild(context.Background(), integrationID)
}

// rebuild projects the integration's current exposure set into served tools.
// An integration that is disabled, withheld, or has no published set serves
// nothing — expressed by replacing its group with no entries at all.
func (s *integrationSurface) rebuild(ctx context.Context, integrationID string) {
	in, err := s.store.GetIntegrationByID(ctx, integrationID)
	if err != nil {
		return
	}
	entries, err := s.buildEntries(ctx, in)
	if err != nil {
		s.auditFn("integration_surface", "account:"+in.AccountID+" integration:"+in.Slug, "error")
		entries = nil
	}
	s.node.SetIntegrationTools(ctx, in.AccountID, integrationID, entries)
	s.auditFn("integration_surface", fmt.Sprintf("account:"+in.AccountID+" integration:%s tools:%d", in.Slug, len(entries)), "rebuilt")
}

func (s *integrationSurface) buildEntries(ctx context.Context, in store.Integration) ([]public.Entry, error) {
	// A withheld integration serves nothing (§6.10), and neither does one the
	// owner disabled. Checking here, rather than at call time, is what makes
	// `tools/list` tell the truth.
	if in.Status == "disabled" || s.chain.Manager.Withheld(in.ID) {
		return nil, nil
	}
	active, err := s.chain.Exposures.ActiveEntries(ctx, in.ID)
	if err != nil || len(active) == 0 {
		return nil, err
	}
	set, err := s.store.LatestExposure(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	cat, err := s.store.GetCatalog(ctx, in.ID, set.CatalogVersion)
	if err != nil {
		return nil, err
	}
	var defs []integrations.ToolDef
	if err := json.Unmarshal([]byte(cat.Tools), &defs); err != nil {
		return nil, err
	}
	byName := map[string]integrations.ToolDef{}
	for _, d := range defs {
		byName[d.Name] = d
	}

	perm := "integration." + in.Slug
	out := make([]public.Entry, 0, len(active))
	for _, en := range active {
		def, ok := byName[en.Tool]
		if !ok {
			// The bound snapshot no longer describes this tool. The stale guard
			// owns that decision; serving it against an unknown schema would be
			// exactly the widening §6.5 forbids.
			continue
		}
		var h mcp.ToolHandler
		switch en.Mode {
		case integrations.ModeMapped:
			continue // §6.6: mapped capabilities are core tools, not per-integration ones
		case integrations.ModeAgent:
			hh, ok := s.agentHandler(in, en, def)
			if !ok {
				continue
			}
			h = hh
		default:
			hh, err := s.pass.Handler(in.AccountID, in.ID, def)
			if err != nil {
				s.auditFn("integration_surface", "account:"+in.AccountID+" tool:"+en.ExposedName, "bad_schema")
				continue
			}
			h = hh
		}
		out = append(out, public.Entry{
			Tool: &mcp.Tool{
				Name:        en.ExposedName,
				Description: def.Description,
				InputSchema: schemaOf(def.InputSchema),
			},
			Rule:    policy.Rule{Tier: policy.TierContact, Permission: perm},
			Handler: h,
		})
	}
	return out, nil
}

// schemaOf decodes a snapshot's input schema, falling back to a permissive
// object rather than dropping the tool: the schema is validated again inside the
// passthrough handler, which is where a mismatch must be refused.
func schemaOf(raw json.RawMessage) *jsonschema.Schema {
	if len(raw) == 0 || string(raw) == "null" {
		return &jsonschema.Schema{Type: "object"}
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return &jsonschema.Schema{Type: "object"}
	}
	return &s
}

// agentHandler parks a call for the owner's agent to answer (SPEC §6.8).
//
// `AgentAnswered.Handler` had no production caller, so nothing could ever create
// a pending request — and `answer_request` on the owner MCP could answer
// requests that could not exist. The handler needs the CALLER, which the
// registry entry cannot carry because one entry serves every contact, so the
// caller is resolved per call from the context the pool put it in.
func (s *integrationSurface) agentHandler(in store.Integration, en integrations.ExposureEntry,
	def integrations.ToolDef) (mcp.ToolHandler, bool) {

	if s.agent == nil {
		return nil, false
	}
	// §6.8's fallback chain: when the owner's agent does not answer in time, a
	// passthrough entry may still serve the call directly.
	var fallback mcp.ToolHandler
	if en.Fallback == integrations.ModePassthrough {
		if h, err := s.pass.Handler(in.AccountID, in.ID, def); err == nil {
			fallback = h
		}
	}
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		c, ok := public.CallerFromContext(ctx)
		if !ok || c.Fingerprint == "" {
			// A parked request must name who is waiting on it, or the owner
			// cannot judge it and the answer cannot be routed back.
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{
				&mcp.TextContent{Text: `{"code":"unavailable"}`}}}, nil
		}
		// Fail SAFE: a caller whose contact row cannot be read parks at the
		// lowest grant — SPEC 7.6 says every surfaced payload carries the
		// flag, and an empty label would be a third state nobody defined.
		trust := "messages_only"
		if row, err := s.store.GetContact(ctx, in.AccountID, c.Fingerprint); err == nil {
			trust = row.TrustFlag
		}
		return s.agent.Handler(in.AccountID, c.Fingerprint, trust, en, fallback)(ctx, req)
	}, true
}

package ownermcp

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

// Build rule 1's divergence, named where a test holds it: the portal is the one door to webhooks
// (ruling A of docs/release/webhooks-2026-10-18.md). No owner MCP tool registers, rotates, pauses,
// resumes or removes one, or lists them, where the cloud's /v1 and owner MCP do all of it. A tool
// that does takes this entry out, and the webhooks README's with it.
func TestNoOwnerMCPToolTouchesAWebhook(t *testing.T) {
	e := newEnv(t)
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if strings.Contains(strings.ToLower(tool.Name+" "+tool.Description), "webhook") {
			t.Errorf("the owner MCP offers %s, which names a webhook: the portal is the one door", tool.Name)
		}
	}
	// The control: the listing is the owner MCP's, not an empty one.
	if !slices.Contains(names, "wait_for_updates") {
		t.Fatalf("the listing has no wait_for_updates: %v", names)
	}
}

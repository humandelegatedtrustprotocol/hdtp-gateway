package public

// An anonymous plaintext caller — no chain that validated, no envelope — is refused
// identity_required on any tools/call (SPEC §5.8; hdtp-gateway #170), whatever the seal policy and
// whether or not the tool is in the guest view, and the refusal writes the gate's one row. The cloud
// answers every plaintext tools/call the same (go-refusals.json, "an anonymous plaintext
// send_message"). A tool outside the guest view used to be answered blocked_or_unknown, and under
// `seal: optional` a guest tool was served.

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// anonymousCall calls tool in plaintext with no identity, through the pool's gate as a node wires
// it (node.go: pool.Gate = Identifier.PoolGate()), under the seal policy given.
func anonymousCall(t *testing.T, s *sealedEnv, seal core.Seal, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	s.id.Seal = seal
	s.pool.Gate = s.id.PoolGate()
	cs, done := connect(t, s.pool, s.acct.ID, "", nil)
	defer done()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

func TestAnAnonymousToolsCallIsIdentityRequired(t *testing.T) {
	for _, seal := range []core.Seal{core.SealOptional, core.SealRequired} {
		for _, tool := range []string{"send_message", "request_contact", "no_such_tool"} {
			s := newSealedEnv(t)
			var rows []string
			s.id.Audit = func(action, resource, outcome string) { rows = append(rows, action+" "+outcome) }
			s.pool.CallAudit = func(_, action, _, outcome string) { rows = append(rows, action+" "+outcome) }
			res := anonymousCall(t, s, seal, tool, map[string]any{"msg_id": "a-1", "text": "hi"})
			if !res.IsError || text(t, res) != `{"code":"identity_required"}` {
				t.Fatalf("seal %s, %s: answered %s, want identity_required", seal, tool, text(t, res))
			}
			if len(rows) != 1 || rows[0] != "identity_gate identity_required" {
				t.Fatalf("seal %s, %s: audited %q, want the gate's one row", seal, tool, rows)
			}
		}
	}
	// The control: an anonymous caller still lists the guest view.
	s := newSealedEnv(t)
	s.id.Seal = core.SealOptional
	s.pool.Gate = s.id.PoolGate()
	cs, done := connect(t, s.pool, s.acct.ID, "", nil)
	defer done()
	if names := toolNames(t, cs); !hasTool(names, "request_contact") || !hasTool(names, core.ToolSealedCall) {
		t.Fatalf("the anonymous guest view lists %v", names)
	}
}

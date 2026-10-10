package public

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// Every refusal is on the audit trail (build rule 7). A built-in tool handed arguments that are not
// its argument object refuses (bad_request, or unavailable when its service is absent), and writes exactly one row saying so, under the tool's
// own name and the caller that sent it. Thirty early refusals — a decode, a cap, a vocabulary —
// used to answer and write nothing, so a peer probing a node with malformed calls left no trace.
// sealed_call is held the same way: a body that is not an envelope.
func TestEveryMalformedCallIsRefusedAndAudited(t *testing.T) {
	var rows []string
	d := ToolDeps{AccountID: "acct", AuditAs: func(kind, action, resource, outcome string) {
		rows = append(rows, kind+" "+action+" "+outcome)
	}}
	entries := BuiltinEntries(d)
	if len(entries) < 10 {
		t.Fatalf("%d built-in tools; the list is not being read", len(entries))
	}
	for _, e := range entries {
		if e.Tool.Name == "get_status" || e.Tool.Name == "get_card" || e.Tool.Name == "remove_contact" {
			// Take no arguments: they do not read the body, so it cannot be malformed for them.
			continue
		}
		rows = rows[:0]
		res, err := e.Handler(context.Background(), &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Name: e.Tool.Name, Arguments: json.RawMessage(`"not an object"`)},
		})
		if err != nil {
			t.Errorf("%s: %v", e.Tool.Name, err)
			continue
		}
		// A tool whose service is absent here (media, calendar) refuses unavailable before it reads
		// the body; that is a refusal too, and held the same way: the code it answered is the row.
		var answered struct{ Code string }
		if res.IsError && len(res.Content) > 0 {
			_ = json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &answered)
		}
		if !res.IsError || (answered.Code != "bad_request" && answered.Code != "unavailable") {
			t.Errorf("%s answered %q to a body that is not its argument object", e.Tool.Name, answered.Code)
			continue
		}
		if len(rows) != 1 || !strings.HasSuffix(rows[0], " "+e.Tool.Name+" "+answered.Code) {
			t.Errorf("%s answered %s and wrote %q, want exactly that one row under its own name", e.Tool.Name, answered.Code, rows)
		}
	}

	s := newSealedEnv(t)
	rows = rows[:0]
	s.deps.AuditAs = func(kind, action, resource, outcome string) { rows = append(rows, kind+" "+action+" "+outcome) }
	res, err := sealedHandler(s.deps)(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: core.ToolSealedCall, Arguments: json.RawMessage(`[1,2,3]`)},
	})
	if err != nil || !res.IsError {
		t.Fatalf("sealed_call took a body that is not an envelope: %+v %v", res, err)
	}
	if len(rows) != 1 || rows[0] != "guest sealed_call envelope_invalid" {
		t.Errorf("sealed_call wrote %q for a body that is not an envelope", rows)
	}
}

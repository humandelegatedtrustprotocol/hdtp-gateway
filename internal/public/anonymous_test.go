package public

// An anonymous plaintext caller — no chain that validated, no envelope — is refused
// identity_required on any tools/call (SPEC §5.8; hdtp-gateway #170), whatever the seal policy and
// whether or not the tool is in the guest view, and the refusal writes the gate's one row. The cloud
// answers every plaintext tools/call the same (go-refusals.json, "an anonymous plaintext
// send_message"). A tool outside the guest view used to be answered blocked_or_unknown, and under
// `seal: optional` a guest tool was served.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
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

// A chain that validated is not anonymous, whatever it earned: a blocked root and a superseded
// leaf are composed as guests with no fingerprint (ResolveTransport, Demote), and a plaintext
// call from either outside the guest view answers what a stranger's does, blocked_or_unknown,
// under each seal policy (SPEC §5.4, §5.8). Only a call with no chain is identity_required.
// Wired as node.mcpHandler wires it: WithFacts, ResolveTransport, WithTransportCaller, StatelessMCP.
func TestADemotedChainAnswersAsAStranger(t *testing.T) {
	for _, seal := range []core.Seal{core.SealOptional, core.SealRequired} {
		s := newSealedEnv(t)
		s.id.Seal = seal
		s.pool.Gate = s.id.PoolGate()
		blocked := newPeer(t, s.nowAt)
		s.pin(t, blocked, "blocked")
		stranger := newPeer(t, s.nowAt)
		old := newPeer(t, s.nowAt)
		renewed := &peer{root: old.root, host: old.host}
		renewed.leaf = renewed.leafFor(t, endpointA, s.nowAt.Add(-30*time.Minute))
		s.pin(t, renewed, "active")
		ask := func(tf TransportFacts) string {
			h := StatelessMCP(func(r *http.Request) *mcp.Server {
				caller := FactsFrom(r.Context()).ClientCertFingerprint
				if tc, ok := TransportCallerFrom(r.Context()); ok {
					caller = tc.Fingerprint
				}
				srv, err := s.pool.ServerFor(r.Context(), s.acct.ID, caller)
				if err != nil {
					t.Fatal(err)
				}
				return srv
			}, mcp.StreamableHTTPOptions{})
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := WithFacts(r.Context(), tf)
				ctx = WithTransportCaller(ctx, s.id.ResolveTransport(ctx, tf))
				h.ServeHTTP(w, r.WithContext(ctx))
			}))
			defer ts.Close()
			cl := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
			cs, err := cl.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cs.Close() }()
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "send_message", Arguments: map[string]any{"text": "x", "msg_id": "m"}})
			if err != nil {
				t.Fatalf("seal %s: %v", seal, err)
			}
			return text(t, res)
		}
		chain := func(p *peer) TransportFacts {
			c, err := hdtpidentity.Parse(p.leaf)
			if err != nil {
				t.Fatal(err)
			}
			return TransportFacts{ClientCertFingerprint: p.fpr(), ClientCertSPKI: c.SPKI, ClientLeaf: p.leaf, ClientEndpoint: c.URIs[0]}
		}
		for name, tf := range map[string]TransportFacts{"blocked": chain(blocked), "superseded": chain(old), "stranger": chain(stranger)} {
			if got := ask(tf); got != `{"code":"blocked_or_unknown"}` {
				t.Errorf("seal %s, %s: answered %s, want blocked_or_unknown", seal, name, got)
			}
		}
		if got := ask(TransportFacts{}); got != `{"code":"identity_required"}` {
			t.Errorf("seal %s, anonymous: answered %s, want identity_required", seal, got)
		}
	}
}

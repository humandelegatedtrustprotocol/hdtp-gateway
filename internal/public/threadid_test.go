package public

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/policy"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/testid"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// HDTP §7 (SEP-0006) at the sealed door: a contact's call whose thread_id is of neither form is
// refused by the identity core's decide, and the node seals the refusal back to the leaf that signed
// (§13.2) as a tool error inside `result`, the answer the tool gives the same call over a client
// certificate, with its code and nothing else (§12). Nothing is dispatched and the msg_id is not
// seen: the same msg_id with a thread_id of a form is then dispatched, the control. The call is
// charged as the contact's call and audited as the contact's, with the why. A renewal the envelope
// carried is learned, as SEP-0006 says it is.
func TestASealedThreadIDOfNeitherFormIsRefusedSealedAndRecordsNothing(t *testing.T) {
	e := newRecvEnv(t)
	dispatched := map[string]int{}
	reg := &Registry{}
	for _, tool := range []string{"get_card", "send_message", "send_media", "book_slot"} {
		name := tool
		reg.Add(Entry{
			Tool: &mcp.Tool{Name: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
			Rule: policy.Rule{Tier: policy.TierContact},
			Handler: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				dispatched[name]++
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran:" + name}}}, nil
			},
		})
	}
	pool := NewPool(reg, StoreResolver(e.st), 8)
	s := &sealedEnv{recvEnv: e, pool: pool, deps: SealedDeps{Pool: pool, Identifier: e.id, AccountID: e.acct.ID, Idem: e.st, Now: func() time.Time { return e.nowAt }}}
	reg.Add(SealedEntries(s.deps)...)
	ctx := context.Background()
	var charged []Charge
	s.pool.Limit = func(_ context.Context, as Charge) *Refusal {
		charged = append(charged, as)
		return nil
	}
	var rows []string
	s.deps.AuditAs = func(kind, action, resource, outcome string) {
		rows = append(rows, kind+" "+resource+" "+outcome)
	}
	p := newPeer(t, s.nowAt.Add(-2*time.Hour))
	s.pin(t, p, "active")

	for _, form := range []string{"chain", "leaf"} {
		for _, tool := range []string{"send_message", "send_media", "book_slot"} {
			for i, c := range testid.ThreadIDs() {
				if c.Code == "" {
					continue
				}
				msgID := "m-" + form + "-" + tool + "-" + strconv.Itoa(i)
				charged, rows = nil, nil
				res := s.call(t, s.sealFrom(t, p, form, tool, map[string]any{"text": "hi", "thread_id": c.ID}, func(o *hdtpidentity.SealOpts) { o.MsgID = msgID }), TransportFacts{})
				result, errObj := s.openedWith(t, res, p, msgID)
				var inner mcp.CallToolResult
				if len(errObj) != 0 || json.Unmarshal(result, &inner) != nil || !inner.IsError || len(inner.Content) != 1 {
					t.Fatalf("%s %s, %s: not a sealed tool error: result %s error %s", form, tool, c.Name, result, errObj)
				}
				if got := inner.Content[0].(*mcp.TextContent).Text; got != `{"code":"`+c.Code+`"}` {
					t.Fatalf("%s %s, %s: sealed %s, want %s", form, tool, c.Name, got, c.Code)
				}
				if dispatched[tool] != 0 {
					t.Fatalf("%s %s, %s: dispatched", form, tool, c.Name)
				}
				if len(charged) != 1 || charged[0] != ChargeCaller {
					t.Fatalf("%s %s, %s: charged %v, want the contact's call", form, tool, c.Name, charged)
				}
				if len(rows) != 1 || !strings.HasPrefix(rows[0], "contact account:"+s.acct.ID+" contact:"+p.fpr()+" why:thread_id ") || !strings.HasSuffix(rows[0], " "+c.Code) {
					t.Fatalf("%s %s, %s: audit %q", form, tool, c.Name, rows)
				}
				// The control, last: the msg_id the refusal did not record, with an id of a form.
				res = s.call(t, s.sealFrom(t, p, form, tool, map[string]any{"text": "hi", "thread_id": "abc"}, func(o *hdtpidentity.SealOpts) { o.MsgID = msgID }), TransportFacts{})
				if result, errObj := s.openedWith(t, res, p, msgID); len(errObj) != 0 || !strings.Contains(string(result), "ran:"+tool) || dispatched[tool] != 1 {
					t.Fatalf("%s %s, %s: the control was not dispatched: %s %s", form, tool, c.Name, result, errObj)
				}
				dispatched[tool] = 0
			}
		}
	}

	// A renewal the refused envelope carried is learned: the pin moves to the newer leaf at the same
	// address.
	renewed := &peer{root: p.root, host: p.host}
	renewed.leaf = renewed.leafFor(t, endpointA, s.nowAt.Add(-time.Hour))
	res := s.call(t, s.sealFrom(t, renewed, "chain", "send_message", map[string]any{"text": "hi", "thread_id": "."}, func(o *hdtpidentity.SealOpts) { o.MsgID = "m-renewed" }), TransportFacts{})
	if result, _ := s.openedWith(t, res, renewed, "m-renewed"); !strings.Contains(string(result), `bad_request`) {
		t.Fatalf("the renewed leaf's call: %s", result)
	}
	c, err := s.st.GetContact(ctx, s.acct.ID, p.fpr())
	if err != nil || string(c.Leaf) != string(renewed.leaf) {
		t.Fatalf("the renewal was not learned: %v", err)
	}
}

// Permission before the thread_id, at both doors (hdtp-gateway #139, the owner's decision): a
// contact without the tool's scope that sends a bad thread_id is told permission_denied over a
// client certificate (the tool is not on its surface) and inside an envelope alike, audited as the
// denial the dispatch writes; a contact with the scope is told the thread_id's refusal. The cloud
// answers in the same order (go-refusals.json holds both).
func TestAContactWithoutTheScopeIsRefusedPermissionBeforeItsThreadID(t *testing.T) {
	s := newSealedEnv(t)
	var rows []string
	s.deps.AuditAs = func(kind, action, resource, outcome string) {
		rows = append(rows, kind+" "+action+" "+resource+" "+outcome)
	}
	s.pool.CallAudit = func(kind, action, resource, outcome string) {
		rows = append(rows, kind+" "+action+" "+resource+" "+outcome)
	}
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active") // message.text only; book_slot needs calendar.book
	args := map[string]any{"msg_id": "b-1", "thread_id": ".", "slot": map[string]any{}}

	res := s.call(t, s.sealFrom(t, p, "chain", "book_slot", args), TransportFacts{})
	result, errObj := s.opened(t, res, p, "book_slot")
	var inner mcp.CallToolResult
	if len(errObj) != 0 || json.Unmarshal(result, &inner) != nil || !inner.IsError || text(t, &inner) != `{"code":"permission_denied"}` {
		t.Fatalf("sealed: answered %s %s, want a sealed permission_denied", result, errObj)
	}
	if want := "contact tools_call caller:" + p.fpr() + " tool:book_slot permission_denied"; len(rows) != 1 || rows[0] != want {
		t.Fatalf("sealed: audited %q, want the one denial %q", rows, want)
	}

	rows = nil
	cs, done := connect(t, s.pool, s.acct.ID, p.fpr(), nil)
	defer done()
	plain, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "book_slot", Arguments: args})
	if err != nil || !plain.IsError || text(t, plain) != `{"code":"permission_denied"}` {
		t.Fatalf("plaintext: answered %v %v, want permission_denied", plain, err)
	}
	if want := "contact tools_call caller:" + p.fpr() + " tool:book_slot permission_denied"; len(rows) != 1 || rows[0] != want {
		t.Fatalf("plaintext: audited %q, want the one denial %q", rows, want)
	}

	// The control: granted the scope, the same call is told its thread_id.
	if err := s.st.UpdateContactPermissions(context.Background(), s.acct.ID, p.fpr(), []string{"message.text", "calendar.book"}, ""); err != nil {
		t.Fatal(err)
	}
	res = s.call(t, s.sealFrom(t, p, "chain", "book_slot", args, func(o *hdtpidentity.SealOpts) { o.MsgID = "m-book_slot-chain-2" }), TransportFacts{})
	result, errObj = s.openedWith(t, res, p, "m-book_slot-chain-2")
	if len(errObj) != 0 || json.Unmarshal(result, &inner) != nil || !inner.IsError || text(t, &inner) != `{"code":"bad_request"}` {
		t.Fatalf("granted: answered %s %s, want a sealed bad_request", result, errObj)
	}
}

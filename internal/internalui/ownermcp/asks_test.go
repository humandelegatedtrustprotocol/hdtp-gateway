package ownermcp

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/asks"
)

// askSurface is the story's ask as an agent sends it: a TLDR, the terms, two ready replies, a field
// to write one's own and a Send button that reads both, with the data model they start from.
const askSurface = `[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + asks.CatalogID + `"}},` +
	`{"version":"v0.9.1","updateComponents":{"surfaceId":"s1","components":[` +
	`{"id":"root","component":"Column","children":["tldr","terms","pick","own","send"]},` +
	`{"id":"tldr","component":"Text","text":"Bob proposes Wed 15:00 for 30 min."},` +
	`{"id":"terms","component":"KeyValue","items":[{"label":"When","value":"Wed 15:00"}]},` +
	`{"id":"pick","component":"ChoicePicker","options":[{"label":"Confirm Wed 15:00","value":"confirm"},{"label":"Ask for Thu instead","value":"thu"}],"value":{"path":"/reply"}},` +
	`{"id":"own","component":"TextField","label":"Write my own","value":{"path":"/own"}},` +
	`{"id":"send-label","component":"Text","text":"Send"},` +
	`{"id":"send","component":"Button","child":"send-label","variant":"primary","action":{"event":{"name":"answer","context":{"reply":{"path":"/reply"},"own":{"path":"/own"}}}}}]}},` +
	`{"version":"v0.9.1","updateDataModel":{"surfaceId":"s1","value":{"reply":[],"own":""}}}]`

// noticeSurface is a done-for-you notice: a TLDR and its terms.
const noticeSurface = `[{"version":"v0.9.1","createSurface":{"surfaceId":"s1","catalogId":"` + asks.CatalogID + `"}},` +
	`{"version":"v0.9.1","updateComponents":{"surfaceId":"s1","components":[` +
	`{"id":"root","component":"Column","children":["tldr","terms"]},` +
	`{"id":"tldr","component":"Text","text":"Booked: Wed 15:00 with Bob."},` +
	`{"id":"terms","component":"KeyValue","items":[{"label":"When","value":"Wed 15:00"}]}]}}]`

// chooseConfirm is the A2UI action the portal sends when the owner picks the first ready reply and
// presses Send.
var chooseConfirm = []byte(`{"version":"v0.9.1","action":{"name":"answer","surfaceId":"s1","sourceComponentId":"send",` +
	`"timestamp":"2026-10-19T10:00:00Z","context":{"reply":["confirm"],"own":""}}}`)

// oversize is the story's ask with a long text beside its TLDR: past asks.MaxSurfaceBytes once
// compacted, as a client sends it, and in every other respect an ask the node takes.
func oversize() string {
	long := `{"id":"long","component":"Text","text":"` + strings.Repeat("x", asks.MaxSurfaceBytes) + `"},`
	return strings.Replace(strings.Replace(askSurface, `"tldr","terms"`, `"tldr","long","terms"`, 1),
		`{"id":"terms"`, long+`{"id":"terms"`, 1)
}

// askEnv is the owner surface with the asks service, over a thread of account A with Bob on it.
type askEnv struct {
	*env
	svc    *asks.Service
	thread string
	cs     *mcp.ClientSession
}

func newAskEnv(t *testing.T, ident func(e *env) auth.Identity) *askEnv {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.st.InsertContact(ctx, store.Contact{AccountID: e.acctA, Fingerprint: "sha256:bob", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	in, err := e.deps.Msg.Record(ctx, e.acctA, "sha256:bob", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: "m1", Text: "Wed 15:00?"})
	if err != nil {
		t.Fatal(err)
	}
	send := func(ctx context.Context, accountID, contactFpr string, in messaging.Input) (messaging.Result, error) {
		return e.deps.Msg.Record(ctx, accountID, contactFpr, messaging.DirOut, in)
	}
	noop := func(string, string, string) {}
	svc := asks.New(e.st, e.deps.Bus, send, noop, noop)
	srv := NewServerWithExtra(e.deps, Extra{Asks: svc}, ident(e))
	ct, st := mcp.NewInMemoryTransports()
	cctx, cancel := context.WithCancel(ctx)
	if _, err := srv.Connect(cctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(cctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); cancel() })
	return &askEnv{env: e, svc: svc, thread: in.ThreadID, cs: cs}
}

func (a *askEnv) put(t *testing.T, tool, account, thread, msg, surface string) (string, bool) {
	t.Helper()
	return callJSON(t, a.cs, tool, map[string]any{"account_id": account, "thread_id": thread, "for_message_id": msg, "surface": json.RawMessage(surface)})
}

func owner(e *env) auth.Identity { return auth.Identity{OwnerID: e.owner} }

// The agent's whole round: ask, ask again (the same ask), list it open, learn from
// wait_for_updates that the owner answered, and read the line through get_ask.
func TestAnAgentAsksItsOwnerAndReadsTheAnswer(t *testing.T) {
	a := newAskEnv(t, owner)
	ctx := context.Background()
	text, isErr := a.put(t, "ask_owner", a.acctA, a.thread, "m1", askSurface)
	if isErr {
		t.Fatalf("ask_owner: %s", text)
	}
	var v asks.View
	if err := json.Unmarshal([]byte(text), &v); err != nil || v.Status != "open" || v.TLDR != "Bob proposes Wed 15:00 for 30 min." {
		t.Fatalf("ask_owner answered %s (%v)", text, err)
	}
	again, _ := a.put(t, "ask_owner", a.acctA, a.thread, "m1", askSurface)
	if !strings.Contains(again, `"id":"`+v.ID+`"`) {
		t.Fatalf("asking again about m1: %s, want %s", again, v.ID)
	}
	listed, _ := callJSON(t, a.cs, "list_asks", map[string]any{"account_id": a.acctA, "status": "open"})
	if !strings.Contains(listed, v.ID) {
		t.Fatalf("list_asks open: %s", listed)
	}
	if listed, _ := callJSON(t, a.cs, "list_asks", map[string]any{"account_id": a.acctA, "thread_id": a.thread}); !strings.Contains(listed, v.ID) {
		t.Fatalf("list_asks of its thread: %s", listed)
	}
	if listed, _ := callJSON(t, a.cs, "list_asks", map[string]any{"account_id": a.acctA, "thread_id": "0123456789abcdef0123456789abcdef"}); strings.Contains(listed, v.ID) {
		t.Fatalf("list_asks of another thread: %s", listed)
	}
	cursor, _ := callJSON(t, a.cs, "wait_for_updates", map[string]any{"account_id": a.acctA})
	var c struct{ Cursor int64 }
	_ = json.Unmarshal([]byte(cursor), &c)

	// The owner taps a ready reply on the portal, which answers through the same service.
	if _, err := a.svc.Answer(ctx, a.acctA, v.ID, chooseConfirm); err != nil {
		t.Fatal(err)
	}
	waited, _ := callJSON(t, a.cs, "wait_for_updates", map[string]any{"account_id": a.acctA, "since": c.Cursor, "timeout_sec": 1})
	var w struct {
		Asks     []askMoved `json:"asks"`
		TimedOut bool       `json:"timed_out"`
	}
	if err := json.Unmarshal([]byte(waited), &w); err != nil || w.TimedOut || len(w.Asks) != 1 ||
		w.Asks[0] != (askMoved{AskID: v.ID, ThreadID: a.thread, Status: "answered", At: w.Asks[0].At}) {
		t.Fatalf("wait_for_updates after the answer: %s", waited)
	}
	got, _ := callJSON(t, a.cs, "get_ask", map[string]any{"account_id": a.acctA, "ask_id": v.ID})
	// The line names the account the ask was put to, by its display name.
	if !strings.Contains(got, `"status":"answered"`) || !strings.Contains(got, `"answer_text":"Work chose: \"Confirm Wed 15:00\""`) {
		t.Fatalf("get_ask after the answer: %s", got)
	}
	if listed, _ := callJSON(t, a.cs, "list_asks", map[string]any{"account_id": a.acctA, "status": "open"}); strings.Contains(listed, v.ID) {
		t.Fatalf("an answered ask is listed open: %s", listed)
	}
}

// Every refusal of the five tools is coded, and the scope check comes before anything is read.
func TestEveryAskToolRefusesByCode(t *testing.T) {
	a := newAskEnv(t, owner)
	ctx := context.Background()
	if _, err := a.deps.Msg.Record(ctx, a.acctA, "sha256:bob", messaging.DirIn, messaging.Input{Origin: messaging.OriginPeer, Sender: messaging.SenderAgent, MsgID: "m2", ThreadID: a.thread, Text: "or Thu?"}); err != nil {
		t.Fatal(err)
	}
	if text, isErr := a.put(t, "notify_owner", a.acctA, a.thread, "m1", noticeSurface); isErr || !strings.Contains(text, `"status":"posted"`) {
		t.Fatalf("the control, a notice: %s", text)
	}
	if text, isErr := a.put(t, "ask_owner", a.acctA, a.thread, "m1", askSurface); isErr {
		t.Fatalf("the control, an ask: %s", text)
	}
	cases := map[string]struct {
		tool string
		args map[string]any
		code string
	}{
		"a second open ask on the thread": {"ask_owner", map[string]any{"account_id": a.acctA, "thread_id": a.thread, "for_message_id": "m2", "surface": json.RawMessage(askSurface)}, "conflict"},
		"an unknown thread":               {"ask_owner", map[string]any{"account_id": a.acctA, "thread_id": "0123456789abcdef0123456789abcdef", "for_message_id": "m1", "surface": json.RawMessage(askSurface)}, "not_found"},
		"a surface that is not A2UI":      {"ask_owner", map[string]any{"account_id": a.acctA, "thread_id": a.thread, "for_message_id": "m2", "surface": map[string]any{"text": "hi"}}, "bad_request"},
		"a surface too large": {"ask_owner", map[string]any{"account_id": a.acctA, "thread_id": a.thread, "for_message_id": "m2",
			"surface": json.RawMessage(oversize())}, "too_large"},
		"a notice that asks":      {"notify_owner", map[string]any{"account_id": a.acctA, "thread_id": a.thread, "for_message_id": "m2", "surface": json.RawMessage(askSurface)}, "bad_request"},
		"arguments not an object": {"ask_owner", map[string]any{"account_id": 7}, "bad_request"},
		"another account":         {"ask_owner", map[string]any{"account_id": "acct_none", "thread_id": a.thread, "for_message_id": "m1", "surface": json.RawMessage(askSurface)}, "permission_denied"},
		"an unknown ask":          {"get_ask", map[string]any{"account_id": a.acctA, "ask_id": "ask_none"}, "not_found"},
		"withdraw an unknown ask": {"withdraw_ask", map[string]any{"account_id": a.acctA, "ask_id": "ask_none"}, "not_found"},
		"a status not offered":    {"list_asks", map[string]any{"account_id": a.acctA, "status": "answered"}, "bad_request"},
		"withdraw elsewhere":      {"withdraw_ask", map[string]any{"account_id": "acct_none", "ask_id": "ask_none"}, "permission_denied"},
		"list elsewhere":          {"list_asks", map[string]any{"account_id": "acct_none"}, "permission_denied"},
		"get elsewhere":           {"get_ask", map[string]any{"account_id": "acct_none", "ask_id": "ask_none"}, "permission_denied"},
	}
	for name, c := range cases {
		text, isErr := callJSON(t, a.cs, c.tool, c.args)
		var r struct{ Code string }
		_ = json.Unmarshal([]byte(text), &r)
		if !isErr || r.Code != c.code {
			t.Errorf("%s: %s (error %v), want code %s", name, text, isErr, c.code)
		}
	}
}

// A token narrowed to account B cannot reach account A's asks, even by the ask's own id.
func TestANarrowTokenCannotReachAnotherAccountsAsk(t *testing.T) {
	a := newAskEnv(t, owner)
	v, err := a.svc.Ask(context.Background(), a.acctA, a.thread, "m1", []byte(askSurface))
	if err != nil {
		t.Fatal(err)
	}
	narrow := newAskEnvOn(t, a, auth.Identity{OwnerID: a.owner, AccountID: a.acctB})
	for _, tool := range []string{"get_ask", "withdraw_ask"} {
		text, isErr := callJSON(t, narrow, tool, map[string]any{"account_id": a.acctA, "ask_id": v.ID})
		if !isErr || !strings.Contains(text, "permission_denied") {
			t.Errorf("%s on A with B's token: %s", tool, text)
		}
		// Naming its own account does not reach A's ask either.
		text, isErr = callJSON(t, narrow, tool, map[string]any{"account_id": a.acctB, "ask_id": v.ID})
		if !isErr || !strings.Contains(text, "not_found") {
			t.Errorf("%s of A's ask under B: %s", tool, text)
		}
	}
}

// newAskEnvOn is another session on a's store and service, as ident.
func newAskEnvOn(t *testing.T, a *askEnv, ident auth.Identity) *mcp.ClientSession {
	t.Helper()
	srv := NewServerWithExtra(a.deps, Extra{Asks: a.svc}, ident)
	ct, st := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); cancel() })
	return cs
}

// The schema a client reads for surface is the catalog's own, its definitions at the tool schema's
// root: one copy, derived where it is enforced. The document resolves on its own, every $ref local,
// and takes the story's ask whole.
func TestTheSurfaceSchemaOnTheWireIsTheCatalogs(t *testing.T) {
	a := newAskEnv(t, owner)
	tools, err := a.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, tool := range tools.Tools {
		kind := map[string]string{"ask_owner": asks.KindAsk, "notify_owner": asks.KindNotice}[tool.Name]
		if kind == "" {
			continue
		}
		found++
		raw, _ := json.Marshal(tool.InputSchema)
		var in struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Defs       json.RawMessage            `json:"$defs"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			t.Fatal(err)
		}
		same := func(what string, got json.RawMessage, want any) {
			w, _ := json.Marshal(want)
			var gotV, wantV any
			if err := json.Unmarshal(got, &gotV); err != nil {
				t.Fatalf("%s's %s: %v", tool.Name, what, err)
			}
			_ = json.Unmarshal(w, &wantV)
			if !reflect.DeepEqual(gotV, wantV) {
				t.Errorf("%s's %s on the wire is not the catalog's:\n%s\nwant\n%s", tool.Name, what, got, w)
			}
		}
		same("surface schema", in.Properties["surface"], asks.SurfaceSchema(kind))
		same("$defs", in.Defs, asks.Defs(kind))
		var doc jsonschema.Schema
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		resolved, err := doc.Resolve(nil)
		if err != nil {
			t.Fatalf("%s's input schema does not resolve on its own: %v", tool.Name, err)
		}
		surface := map[string]string{asks.KindAsk: askSurface, asks.KindNotice: noticeSurface}[kind]
		var args any
		_ = json.Unmarshal([]byte(`{"account_id":"a","thread_id":"t","for_message_id":"m","surface":`+surface+`}`), &args)
		if err := resolved.Validate(args); err != nil {
			t.Errorf("%s's input schema refuses the story's %s: %v", tool.Name, kind, err)
		}
	}
	if found != 2 {
		t.Fatalf("found %d of ask_owner and notify_owner", found)
	}
}

// The agent's MCP client, @mastra/mcp 2.4.1, drops a listed tool with only a warning when its input
// schema is more than 128 subschemas deep or holds more than 10000 of them (dist/index.js,
// getJsonSchemaComplexityError, which walks the subschema keywords and does not follow $ref). Every
// owner tool, the asks' surface included, stays at a tenth of both.
func TestEveryOwnerToolsSchemaIsWellInsideTheAgentClientsBounds(t *testing.T) {
	a := newAskEnv(t, owner)
	tools, err := a.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, tool := range tools.Tools {
		raw, _ := json.Marshal(tool.InputSchema)
		var s any
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		nodes, depth := schemaSize(s, 0)
		if nodes > 1000 || depth > 12 {
			t.Errorf("%s's input schema holds %d subschemas, %d deep: over a tenth of what the agent's client keeps", tool.Name, nodes, depth)
		}
		if tool.Name == "ask_owner" || tool.Name == "notify_owner" {
			seen++
		}
	}
	if seen != 2 {
		t.Fatalf("listed %d of ask_owner and notify_owner", seen)
	}
}

// schemaSize counts a schema's subschemas and its deepest one (the root at 0), by the keywords the
// agent's client walks.
func schemaSize(v any, d int) (nodes, depth int) {
	m, ok := v.(map[string]any)
	if !ok {
		return 0, 0
	}
	nodes, depth = 1, d
	add := func(c any) {
		n, dd := schemaSize(c, d+1)
		nodes += n
		depth = max(depth, dd)
	}
	for _, k := range []string{"$defs", "definitions", "properties", "patternProperties", "dependentSchemas", "dependencies"} {
		if sub, ok := m[k].(map[string]any); ok {
			for _, c := range sub {
				add(c)
			}
		}
	}
	for _, k := range []string{"prefixItems", "allOf", "anyOf", "oneOf", "items"} {
		if sub, ok := m[k].([]any); ok {
			for _, c := range sub {
				add(c)
			}
		}
	}
	for _, k := range []string{"additionalProperties", "unevaluatedProperties", "additionalItems", "unevaluatedItems", "items", "contains", "propertyNames", "not", "if", "then", "else", "contentSchema"} {
		if c, ok := m[k]; ok {
			add(c)
		}
	}
	return nodes, depth
}

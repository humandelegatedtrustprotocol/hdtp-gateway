package ownermcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

// wantOwnerHints is what each owner tool says of itself, as read-only, destructive, idempotent,
// open-world: the values BatonDeck's owner MCP gives the same action (gateway/src/mcp/owner/
// actions.ts: `effect`, `idempotent`, `reaches`), and for the three tools the cloud has no action
// for, or decided apart, the plan of 2026-10-10 (delete_thread, list_passkeys, remove_passkey).
// Open world is true only where the tool reaches a peer. Written here a second time so the
// registrations are held to it.
var wantOwnerHints = map[string][4]bool{
	"list_accounts":          {true, false, true, false},
	"get_inbox":              {true, false, true, false},
	"read_thread":            {true, false, true, false},
	"delete_thread":          {false, true, true, false},
	"send_to_contact":        {false, false, false, true},
	"list_contacts":          {true, false, true, false},
	"approve_contact":        {false, true, false, true},
	"reject_contact":         {false, true, false, true},
	"block_contact":          {false, true, true, false},
	"unblock_contact":        {false, true, false, false},
	"remove_contact":         {false, true, false, true},
	"list_pending_addresses": {true, false, true, false},
	"approve_address":        {false, true, false, false},
	"reject_address":         {false, true, false, false},
	"set_permissions":        {false, true, true, false},
	"rename_contact":         {false, true, true, false},
	"refresh_contact":        {false, true, false, true},
	"set_trust_flag":         {false, true, true, false},
	"create_invite":          {false, false, false, false},
	"list_invites":           {true, false, true, false},
	"revoke_invite":          {false, true, false, false},
	"list_pending":           {true, false, true, false},
	"answer_request":         {false, true, false, true},
	"export_card":            {true, false, true, false},
	"identity_certificate":   {true, false, true, false},
	"list_passkeys":          {true, false, true, false},
	"remove_passkey":         {false, true, true, false},
	"call_contact":           {false, true, false, true},
	"list_integrations":      {true, false, true, false},
	"set_exposure":           {false, true, true, false},
	"add_contact":            {false, true, false, true},
	"audit_query":            {true, false, true, false},
	"wait_for_updates":       {true, false, true, false},
	"digest":                 {true, false, true, false},
}

// everyTool is a server with every optional tool registered: each Extra field and
// Deps.RefreshContact set to a stub that is never called, since only the listing is read.
func everyTool() *mcp.Server {
	d := Deps{RefreshContact: func(context.Context, string, string) (string, string, error) { return "", "", nil }}
	e := Extra{
		Card: func(context.Context, string) (string, error) { return "", nil },
		Certificate: func(context.Context, string) (identity.CertificateInfo, error) {
			return identity.CertificateInfo{}, nil
		},
		Passkeys:      func(context.Context) ([]auth.PasskeyInfo, error) { return nil, nil },
		RemovePasskey: func(context.Context, string) error { return nil },
		CallContact:   func(context.Context, string, string, string, map[string]any) (string, error) { return "", nil },
		Audit: func(context.Context, string, int, func(string) bool) ([]store.AuditRow, error) {
			return nil, nil
		},
		Log:          func(string, string, string) {},
		Integrations: func(context.Context, string) ([]IntegrationView, error) { return nil, nil },
		SetExposure:  func(context.Context, string, string, []string) error { return nil },
		AddContact: func(context.Context, string, string, string, string, string) (AddContactResult, error) {
			return AddContactResult{}, nil
		},
	}
	return NewServerWithExtra(d, e, auth.Identity{})
}

// Every owner tool states its four hints on the wire, as the owner MCP's transport sends them
// (go-sdk's Streamable HTTP handler, stateless, answering JSON), with the table's values; and
// the listing is exactly the tools the table names, so a tool added without a row fails here.
func TestEveryOwnerToolStatesItsFourHintsOnTheWire(t *testing.T) {
	srv := everyTool()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	req := httptest.NewRequest(http.MethodPost, "/owner/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("tools/list answer does not decode: %v\n%s", err, rec.Body.String())
	}

	keys := [4]string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
	var served []string
	for _, raw := range env.Result.Tools {
		var tl struct {
			Name        string                     `json:"name"`
			Annotations map[string]json.RawMessage `json:"annotations"`
		}
		if err := json.Unmarshal(raw, &tl); err != nil {
			t.Fatalf("a tool on the wire does not decode: %v\n%s", err, raw)
		}
		served = append(served, tl.Name)
		want, ok := wantOwnerHints[tl.Name]
		if !ok {
			t.Errorf("%s is served and the hint table does not name it", tl.Name)
			continue
		}
		if len(tl.Annotations) != 4 {
			t.Errorf("%s: annotations carry %d keys, want exactly the four hints\n%s", tl.Name, len(tl.Annotations), raw)
			continue
		}
		var got [4]bool
		for i, k := range keys {
			switch string(tl.Annotations[k]) {
			case "true":
				got[i] = true
			case "false":
			default:
				t.Errorf("%s: %s is %q on the wire, want true or false", tl.Name, k, tl.Annotations[k])
			}
		}
		if got != want {
			t.Errorf("%s hints (ro, de, id, ow) = %v on the wire, want %v", tl.Name, got, want)
		}
	}
	sort.Strings(served)
	want := make([]string, 0, len(wantOwnerHints))
	for name := range wantOwnerHints {
		want = append(want, name)
	}
	sort.Strings(want)
	if strings.Join(served, ",") != strings.Join(want, ",") {
		t.Fatalf("the owner surface serves\n  %v\nand the hint table names\n  %v", served, want)
	}
}

// The listing a client decodes carries the same four values: the structs the SDK hands a client
// agree with the bytes (a pointer left nil would decode as absent, which the wire test catches
// first; this holds the two readings together over one real session).
func TestAClientReadsTheOwnerHintsTheWireCarries(t *testing.T) {
	ctx := context.Background()
	srv := everyTool()
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		a := tl.Annotations
		if a == nil || a.DestructiveHint == nil || a.OpenWorldHint == nil {
			t.Fatalf("%s: a client decoded no complete annotations", tl.Name)
		}
		got := [4]bool{a.ReadOnlyHint, *a.DestructiveHint, a.IdempotentHint, *a.OpenWorldHint}
		if want := wantOwnerHints[tl.Name]; got != want {
			t.Errorf("%s: a client reads %v, the table says %v", tl.Name, got, want)
		}
	}
}

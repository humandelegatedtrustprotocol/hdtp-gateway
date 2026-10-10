package cli

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/messaging"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/services/integrationchain"
)

// fourHints reads annotations as a listing carries them and fails unless they are exactly the
// four hints, each a JSON boolean; it returns them as read-only, destructive, idempotent, open world.
func fourHints(t *testing.T, annotations json.RawMessage) [4]bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(annotations, &m); err != nil {
		t.Fatalf("annotations do not decode: %v\n%s", err, annotations)
	}
	if len(m) != 4 {
		t.Fatalf("annotations carry %d keys, want exactly the four hints\n%s", len(m), annotations)
	}
	var got [4]bool
	for i, k := range [4]string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
		switch string(m[k]) {
		case "true":
			got[i] = true
		case "false":
		default:
			t.Fatalf("%s is %q on the wire, want true or false", k, m[k])
		}
	}
	return got
}

// What a contact is told about an exposed integration tool, from what the snapshot stored: the
// hints the upstream stated, MCP's default for each it did not (or stated as something that is
// not a boolean), open world true whatever it said, and the worst case for an agent-answered
// exposure. The same table holds the cloud's `servedAnnotations` (batondeck
// gateway/test/integrations.test.ts).
func TestServedAnnotationsFillTheDefaultsAndStateOpenWorld(t *testing.T) {
	cases := []struct {
		name   string
		stored string
		mode   string
		want   [4]bool // ro, de, id, ow
	}{
		{"none stored", "", integrations.ModePassthrough, [4]bool{false, true, false, true}},
		{"null stored", "null", integrations.ModePassthrough, [4]bool{false, true, false, true}},
		{"empty object", "{}", integrations.ModePassthrough, [4]bool{false, true, false, true}},
		{"read-only upstream", `{"readOnlyHint":true}`, integrations.ModePassthrough, [4]bool{true, true, false, true}},
		{"additive, idempotent", `{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true}`, integrations.ModePassthrough, [4]bool{false, false, true, true}},
		{"closed world is still open from here", `{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}`, integrations.ModePassthrough, [4]bool{true, false, true, true}},
		{"a hint that is not a boolean is the default", `{"readOnlyHint":"yes","destructiveHint":0,"idempotentHint":null}`, integrations.ModePassthrough, [4]bool{false, true, false, true}},
		{"a null destructive hint is the default, not false", `{"destructiveHint":null}`, integrations.ModePassthrough, [4]bool{false, true, false, true}},
		{"a title is not re-served", `{"title":"Find","readOnlyHint":true}`, integrations.ModePassthrough, [4]bool{true, true, false, true}},
		{"not an object", `[true]`, integrations.ModePassthrough, [4]bool{false, true, false, true}},
		{"agent-answered, read-only upstream", `{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}`, integrations.ModeAgent, [4]bool{false, true, false, true}},
		{"agent-answered, nothing stored", "", integrations.ModeAgent, [4]bool{false, true, false, true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ann := servedAnnotations(json.RawMessage(tc.stored), tc.mode)
			raw, err := json.Marshal(ann)
			if err != nil {
				t.Fatal(err)
			}
			if got := fourHints(t, raw); got != tc.want {
				t.Fatalf("stored %q in %s mode: served %v, want %v", tc.stored, tc.mode, got, tc.want)
			}
		})
	}
}

// The projection serves the normalised hints on every entry it builds (SPEC §6.5): a
// passthrough tool with the upstream's hints, one with none, and an agent-answered one, read as the
// tool definitions the registry will list.
func TestTheIntegrationSurfaceServesEveryExposedToolWithItsFourHints(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := migrated(t, dir)
	defer st.Close()

	chain := integrationchain.Build(st, nil, nil, "", func(string, string, string) {}, nil, nil, nil)
	surf := &integrationSurface{
		store: st, chain: chain, auditFn: func(string, string, string) {},
		pass:  &integrations.Passthrough{Manager: chain.Manager},
		agent: &integrations.AgentAnswered{Store: st, Bus: messaging.NewBus(st), WaitBudget: 50 * time.Millisecond, TTL: time.Hour},
	}
	acct, err := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "me", DisplayName: "Me", Algo: "p256"})
	if err != nil {
		t.Fatal(err)
	}
	in, err := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "desk", Transport: "streamable-http",
		Endpoint: "https://upstream.invalid", AuthKind: "none", Status: "ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertCatalog(ctx, store.Catalog{IntegrationID: in.ID, Version: 1, Tools: `[` +
		`{"name":"lookup","description":"look up","input_schema":{"type":"object"},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false},"hash":"h1"},` +
		`{"name":"file","description":"file a ticket","input_schema":{"type":"object"},"hash":"h2"},` +
		`{"name":"ask","description":"ask the owner","input_schema":{"type":"object"},"annotations":{"readOnlyHint":true},"hash":"h3"}]`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertExposure(ctx, store.Exposure{IntegrationID: in.ID, Version: 1, CatalogVersion: 1, Entries: `[` +
		`{"tool":"lookup","mode":"passthrough","exposed_name":"desk_lookup","confirmed_hash":"h1"},` +
		`{"tool":"file","mode":"passthrough","exposed_name":"desk_file","confirmed_hash":"h2"},` +
		`{"tool":"ask","mode":"agent","exposed_name":"desk_ask","confirmed_hash":"h3"}]`,
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := surf.buildEntries(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][4]bool{
		"desk_lookup": {true, false, true, true},  // the upstream's hints; open world from here
		"desk_file":   {false, true, false, true}, // nothing stated: the defaults
		"desk_ask":    {false, true, false, true}, // agent-answered: the worst case, whatever the upstream said
	}
	if len(entries) != len(want) {
		t.Fatalf("built %d entries, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		raw, err := json.Marshal(e.Tool)
		if err != nil {
			t.Fatal(err)
		}
		var tl struct {
			Name        string          `json:"name"`
			Annotations json.RawMessage `json:"annotations"`
		}
		if err := json.Unmarshal(raw, &tl); err != nil {
			t.Fatal(err)
		}
		w, ok := want[tl.Name]
		if !ok {
			t.Fatalf("built %s, which this test did not publish", tl.Name)
		}
		if got := fourHints(t, tl.Annotations); got != w {
			t.Errorf("%s: served %v, want %v", tl.Name, got, w)
		}
	}
}

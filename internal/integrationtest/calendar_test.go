package integrationtest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ics "github.com/arran4/golang-ical"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tech-sumit/pact-gateway/internal/core/policy"
	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
	"github.com/tech-sumit/pact-gateway/internal/integrations/providers"
	"github.com/tech-sumit/pact-gateway/internal/integrations/recipes"
	"github.com/tech-sumit/pact-gateway/internal/public"
)

// Tuesday 2026-08-25, a workday under the default 09:00–17:00 policy.
var demoDay = time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

// fakeGCal speaks the nspady/google-calendar-mcp tool shapes the shipped
// recipe binds: get-freebusy returns busy blocks, create-event returns an id.
func fakeGCal(t *testing.T) (string, *[]map[string]any) {
	t.Helper()
	created := &[]map[string]any{}
	srv := mcp.NewServer(&mcp.Implementation{Name: "google-calendar-mcp", Version: "0"}, nil)
	srv.AddTool(&mcp.Tool{Name: "get-freebusy", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			body, _ := json.Marshal(map[string]any{"calendars": map[string]any{"primary": map[string]any{"busy": []any{
				map[string]any{"start": demoDay.Add(10 * time.Hour).Format(time.RFC3339), "end": demoDay.Add(12 * time.Hour).Format(time.RFC3339)},
			}}}})
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
		})
	srv.AddTool(&mcp.Tool{Name: "create-event", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args map[string]any
			_ = json.Unmarshal(req.Params.Arguments, &args)
			*created = append(*created, args)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"id":"evt-777"}`}}}, nil
		})
	srv.AddTool(&mcp.Tool{Name: "delete-event", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{}`}}}, nil
		})
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(hs.Close)
	return hs.URL, created
}

type availArgs struct {
	WindowStart     string `json:"window_start"`
	WindowEnd       string `json:"window_end"`
	DurationMinutes int    `json:"duration_minutes"`
}

type bookArgs struct {
	MsgID   string `json:"msg_id"`
	Start   string `json:"start"`
	End     string `json:"end"`
	Subject string `json:"subject"`
}

// P3 exit (PLAN P3-10): a contact's agent calls check_availability and
// book_slot on the owner's public surface; both are served by the Calendar
// provider bound through the shipped nspady recipe to an in-test Google
// Calendar MCP fake — and gated by PACT core permissions, not vendor names.
func TestP3ExitContactBooksCalendarSlot(t *testing.T) {
	ctx := context.Background()
	upstream, created := fakeGCal(t)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p3.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	acct, _ := st.CreateAccount(ctx, store.CreateAccountParams{Slug: "alice", DisplayName: "Alice", Algo: "p256"})
	in, _ := st.InsertIntegration(ctx, store.Integration{
		AccountID: acct.ID, Slug: "gcal", Transport: "streamable-http", Endpoint: upstream,
	})

	// integration lifecycle exactly as serve wires it
	m := &integrations.Manager{Store: st, PingEvery: -1}
	defer func() { _ = m.Disconnect(context.Background(), in.ID) }()
	cat := &integrations.Cataloger{Store: st, Manager: m}
	exps := &integrations.Exposures{Store: st}
	cat.OnMinted = func(id string) { _, _, _ = exps.Reconcile(context.Background(), id) }
	m.OnConnected = func(id string) { _, _, _ = cat.Refresh(context.Background(), id) }
	if err := m.Connect(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	all, err := recipes.All()
	if err != nil {
		t.Fatal(err)
	}
	recipe := all["nspady"]
	// mapped entries expose PACT's own capability names (SPEC §6.5/§6.6)
	if _, err := exps.Publish(ctx, in.ID, []integrations.ExposureEntry{
		{Tool: "get-freebusy", Mode: integrations.ModeMapped, Recipe: "nspady", ExposedName: "check_availability"},
		{Tool: "create-event", Mode: integrations.ModeMapped, Recipe: "nspady", ExposedName: "book_slot"},
	}); err != nil {
		t.Fatal(err)
	}
	active, _ := exps.ActiveEntries(ctx, in.ID)
	if len(active) != 2 {
		t.Fatalf("exposed: %+v", active)
	}

	// the provider, bound to the live upstream session
	cal := &providers.Calendar{
		Call: providers.ManagerCaller(m, in.ID), Recipe: recipe, Store: st, Account: acct.ID,
		Now: func() time.Time { return demoDay },
	}

	// the public registry: PACT core permissions gate mapped capabilities
	pubReg := &public.Registry{}
	pubReg.Add(
		public.Entry{
			Tool: &mcp.Tool{Name: "check_availability", InputSchema: json.RawMessage(`{"type":"object","required":["window_start","window_end","duration_minutes"]}`)},
			Rule: policy.Rule{Tier: policy.TierContact, Permission: "calendar.availability"},
			Handler: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var a availArgs
				if err := json.Unmarshal(req.Params.Arguments, &a); err != nil {
					return errResult("bad_request"), nil
				}
				ws, err1 := time.Parse(time.RFC3339, a.WindowStart)
				we, err2 := time.Parse(time.RFC3339, a.WindowEnd)
				if err1 != nil || err2 != nil || a.DurationMinutes <= 0 {
					return errResult("bad_request"), nil
				}
				slots, err := cal.CheckAvailability(ctx, ws, we, time.Duration(a.DurationMinutes)*time.Minute)
				if err != nil {
					return errResult("unavailable"), nil
				}
				b, _ := json.Marshal(map[string]any{"slots": slots})
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
			},
		},
		public.Entry{
			Tool: &mcp.Tool{Name: "book_slot", InputSchema: json.RawMessage(`{"type":"object","required":["msg_id","start","end","subject"]}`)},
			Rule: policy.Rule{Tier: policy.TierContact, Permission: "calendar.book"},
			Handler: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var a bookArgs
				if err := json.Unmarshal(req.Params.Arguments, &a); err != nil {
					return errResult("bad_request"), nil
				}
				s, err1 := time.Parse(time.RFC3339, a.Start)
				e, err2 := time.Parse(time.RFC3339, a.End)
				if err1 != nil || err2 != nil || a.MsgID == "" {
					return errResult("bad_request"), nil
				}
				caller, ok := public.CallerFromContext(ctx)
				if !ok {
					return errResult("unavailable"), nil
				}
				ack, err := cal.BookSlot(ctx, caller.Fingerprint, a.MsgID, providers.Slot{Start: s, End: e}, a.Subject)
				if err != nil {
					return errResult("unavailable"), nil
				}
				b, _ := json.Marshal(ack)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
			},
		},
	)
	pool := public.NewPool(pubReg, public.StoreResolver(st), 8)

	// two contacts: Bella may check + book; Carl may only check
	_, _ = st.InsertContact(ctx, store.Contact{AccountID: acct.ID, Fingerprint: "sha256:bella", Status: "active", SPKI: []byte{1},
		Permissions: []string{"calendar.availability", "calendar.book"}})
	_, _ = st.InsertContact(ctx, store.Contact{AccountID: acct.ID, Fingerprint: "sha256:carl", Status: "active", SPKI: []byte{2},
		Permissions: []string{"calendar.availability"}})

	bella := connectCaller(t, pool, acct.ID, "sha256:bella")
	carl := connectCaller(t, pool, acct.ID, "sha256:carl")

	// Bella: availability → ≤5 slots, none overlapping the 10:00–12:00 busy block
	res := callTool(t, bella, "check_availability", map[string]any{
		"window_start": demoDay.Format(time.RFC3339), "window_end": demoDay.Add(24 * time.Hour).Format(time.RFC3339),
		"duration_minutes": 30,
	})
	var out struct{ Slots []providers.Slot }
	if err := json.Unmarshal([]byte(res), &out); err != nil || len(out.Slots) == 0 || len(out.Slots) > providers.MaxSlots {
		t.Fatalf("availability: %s %v", res, err)
	}
	for _, s := range out.Slots {
		if s.Start.Before(demoDay.Add(12*time.Hour)) && demoDay.Add(10*time.Hour).Before(s.End) {
			t.Fatalf("slot overlaps busy block: %+v", s)
		}
	}
	if strings.Contains(res, "busy") {
		t.Fatal("raw free/busy leaked to the contact")
	}

	// Bella books the first slot: booking_id + parsing ICS; upstream created it
	first := out.Slots[0]
	book := callTool(t, bella, "book_slot", map[string]any{
		"msg_id": "b-1", "start": first.Start.Format(time.RFC3339), "end": first.End.Format(time.RFC3339), "subject": "Tea",
	})
	var ack providers.BookingAck
	if err := json.Unmarshal([]byte(book), &ack); err != nil || ack.BookingID == "" {
		t.Fatalf("booking: %s %v", book, err)
	}
	if _, err := ics.ParseCalendar(strings.NewReader(ack.ICS)); err != nil {
		t.Fatalf("ics does not parse: %v", err)
	}
	if len(*created) != 1 || (*created)[0]["summary"] != "Tea" {
		t.Fatalf("upstream create-event: %+v", *created)
	}
	// replaying the same msg_id returns the same ack and creates nothing new
	if again := callTool(t, bella, "book_slot", map[string]any{
		"msg_id": "b-1", "start": first.Start.Format(time.RFC3339), "end": first.End.Format(time.RFC3339), "subject": "Tea",
	}); again != book || len(*created) != 1 {
		t.Fatalf("idempotent replay broke: %s (created=%d)", again, len(*created))
	}

	// Carl: may check, may NOT book — book_slot is not even listed for him
	if _, err := carl.CallTool(ctx, &mcp.CallToolParams{Name: "check_availability", Arguments: map[string]any{
		"window_start": demoDay.Format(time.RFC3339), "window_end": demoDay.Add(24 * time.Hour).Format(time.RFC3339), "duration_minutes": 30,
	}}); err != nil {
		t.Fatalf("carl availability: %v", err)
	}
	tools, _ := carl.ListTools(ctx, nil)
	for _, tl := range tools.Tools {
		if tl.Name == "book_slot" {
			t.Fatal("book_slot listed without calendar.book")
		}
	}
	if len(*created) != 1 {
		t.Fatal("something booked without permission")
	}
}

func errResult(code string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: `{"code":"` + code + `"}`}}}
}

func connectCaller(t *testing.T, pool *public.Pool, accountID, fpr string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	srv, err := pool.ServerFor(ctx, accountID, fpr)
	if err != nil {
		t.Fatal(err)
	}
	ct, stt := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, stt, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: fpr, Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

package providers

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ics "github.com/arran4/golang-ical"

	"github.com/tech-sumit/pact-gateway/internal/core/store"
	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

func freebusyRecipe() integrations.Recipe {
	return integrations.Recipe{
		Name: "fake-fb",
		Capabilities: map[string]integrations.Binding{
			"check_availability": {
				Tool: "get-freebusy", Kind: "freebusy",
				Args: map[string]string{"timeMin": "$window_start", "timeMax": "$window_end"},
				Out:  map[string]string{"busy": "calendars.primary.busy", "busy_start": "start", "busy_end": "end"},
			},
			"book_slot": {
				Tool: "create-event", Kind: "create",
				Args: map[string]string{"summary": "$subject", "start": "$start", "end": "$end"},
				Out:  map[string]string{"event_id": "id"},
			},
			"cancel_booking": {
				Tool: "delete-event", Kind: "delete",
				Args: map[string]string{"eventId": "$event_id"},
			},
		},
	}
}

func idemStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "cal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

// Tuesday 2026-08-25.
var day = time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)

func TestFreebusyNeverLeaksRawAndCapsAtFive(t *testing.T) {
	var lastTool atomic.Pointer[string]
	c := &Calendar{
		Recipe: freebusyRecipe(), Store: idemStore(t), Account: "a",
		Call: func(_ context.Context, tool string, args map[string]any) (any, error) {
			lastTool.Store(&tool)
			if args["timeMin"] == "" || args["timeMax"] == "" {
				t.Fatal("window not mapped")
			}
			return map[string]any{"calendars": map[string]any{"primary": map[string]any{"busy": []any{
				map[string]any{"start": day.Add(10 * time.Hour).Format(time.RFC3339), "end": day.Add(11 * time.Hour).Format(time.RFC3339)},
			}}}}, nil
		},
	}
	// window 00:00–24:00, 30-minute slots: plenty of free slots exist —
	// the answer must still be ≤5 and never overlap busy. There is no
	// working-hours filter (the owner's decision of 2026-09-25): the calendar's
	// free time is the answer, so the earliest free slot is midnight.
	slots, err := c.CheckAvailability(context.Background(), day, day.Add(24*time.Hour), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) == 0 || len(slots) > MaxSlots {
		t.Fatalf("slot count: %d", len(slots))
	}
	if !slots[0].Start.Equal(day) {
		t.Fatalf("the earliest free slot is %v, want midnight: a working-hours filter is back", slots[0].Start)
	}
	busyS, busyE := day.Add(10*time.Hour), day.Add(11*time.Hour)
	for _, s := range slots {
		if s.Start.Before(busyE) && busyS.Before(s.End) {
			t.Fatalf("slot overlaps busy: %+v", s)
		}
	}
	if *lastTool.Load() != "get-freebusy" {
		t.Fatalf("tool: %s", *lastTool.Load())
	}
}

func TestSuggestKindOrdersAndCaps(t *testing.T) {
	rec := integrations.Recipe{Name: "fake-sg", Capabilities: map[string]integrations.Binding{
		"check_availability": {
			Tool: "suggest_time", Kind: "suggest",
			Args: map[string]string{"time_min": "$window_start", "time_max": "$window_end", "duration_minutes": "$duration_minutes"},
			Out:  map[string]string{"slots": "suggestions", "slot_start": "start_time", "slot_end": "end_time"},
		},
	}}
	mk := func(h int) map[string]any {
		return map[string]any{
			"start_time": day.Add(time.Duration(h) * time.Hour).Format(time.RFC3339),
			"end_time":   day.Add(time.Duration(h)*time.Hour + 30*time.Minute).Format(time.RFC3339),
		}
	}
	c := &Calendar{Recipe: rec, Store: idemStore(t), Account: "a",
		Call: func(_ context.Context, tool string, _ map[string]any) (any, error) {
			// 8 suggestions, out of order: the cap keeps the earliest five
			return map[string]any{"suggestions": []any{mk(22), mk(9), mk(10), mk(6), mk(11), mk(12), mk(13), mk(14)}}, nil
		}}
	slots, err := c.CheckAvailability(context.Background(), day, day.Add(24*time.Hour), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != MaxSlots {
		t.Fatalf("want exactly %d slots, got %d", MaxSlots, len(slots))
	}
	// 06:00 is offered: what the upstream suggests is not filtered by hours.
	for i, want := range []int{6, 9, 10, 11, 12} {
		if slots[i].Start.Hour() != want {
			t.Fatalf("slot %d starts at %v, want %02d:00", i, slots[i].Start, want)
		}
	}
}

func TestBookSlotICSAndIdempotency(t *testing.T) {
	var calls atomic.Int64
	c := &Calendar{
		Recipe: freebusyRecipe(), Store: idemStore(t), Account: "a",
		Now: func() time.Time { return day },
		Call: func(_ context.Context, tool string, args map[string]any) (any, error) {
			calls.Add(1)
			if tool != "create-event" || args["summary"] != "Tea with Bella" {
				t.Fatalf("bad call: %s %v", tool, args)
			}
			return map[string]any{"id": "evt-42"}, nil
		},
	}
	slot := Slot{Start: day.Add(10 * time.Hour), End: day.Add(10*time.Hour + 30*time.Minute)}
	ack, err := c.BookSlot(context.Background(), "sha256:bella", "m1", slot, "Tea with Bella")
	if err != nil || ack.BookingID == "" {
		t.Fatalf("%+v %v", ack, err)
	}
	// ICS parses and carries the slot
	cal, err := ics.ParseCalendar(strings.NewReader(ack.ICS))
	if err != nil || len(cal.Events()) != 1 {
		t.Fatalf("ics: %v", err)
	}
	if sum := cal.Events()[0].GetProperty(ics.ComponentPropertySummary).Value; sum != "Tea with Bella" {
		t.Fatalf("summary: %q", sum)
	}
	// replay: same msg_id returns the SAME ack without a second upstream call
	ack2, err := c.BookSlot(context.Background(), "sha256:bella", "m1", slot, "Tea with Bella")
	if err != nil || ack2 != ack || calls.Load() != 1 {
		t.Fatalf("replay: %+v %v calls=%d", ack2, err, calls.Load())
	}
	// booking_id maps back to the upstream event id
	if id, err := DecodeBookingID(ack.BookingID); err != nil || id != "evt-42" {
		t.Fatalf("decode: %q %v", id, err)
	}
}

func TestCancelBookingMapsBack(t *testing.T) {
	var gotArgs map[string]any
	c := &Calendar{Recipe: freebusyRecipe(), Store: idemStore(t), Account: "a",
		Call: func(_ context.Context, tool string, args map[string]any) (any, error) {
			if tool != "delete-event" {
				t.Fatalf("tool: %s", tool)
			}
			gotArgs = args
			return map[string]any{}, nil
		}}
	if err := c.CancelBooking(context.Background(), EncodeBookingID("evt-9")); err != nil {
		t.Fatal(err)
	}
	if gotArgs["eventId"] != "evt-9" {
		t.Fatalf("args: %v", gotArgs)
	}
	if err := c.CancelBooking(context.Background(), "not-a-booking"); err == nil {
		t.Fatal("bad booking id accepted")
	}
}

func TestStatusLocalAndRecipeSourced(t *testing.T) {
	s := &Status{Local: func(context.Context) (string, error) { return "busy", nil }}
	if v, _ := s.GetStatus(context.Background()); v != "busy" {
		t.Fatalf("local: %s", v)
	}
	rec := integrations.Recipe{Name: "st", Capabilities: map[string]integrations.Binding{
		"get_status": {Tool: "presence", Kind: "status", Out: map[string]string{"status": "state"}},
	}}
	s2 := &Status{Recipe: &rec, Call: func(_ context.Context, tool string, _ map[string]any) (any, error) {
		return map[string]any{"state": "in-a-meeting"}, nil
	}}
	if v, err := s2.GetStatus(context.Background()); err != nil || v != "in-a-meeting" {
		t.Fatalf("recipe: %s %v", v, err)
	}
}

// A per-install parameter must reach the upstream call on EVERY capability. The
// mapping DSL has only field references and constants, so a server that needs a
// value only this install knows — a CalDAV collection URL, a calendar id — could
// not be mapped at all before `$cfg.<name>` existed. Google's servers hid this by
// defaulting to the primary calendar.
func TestPerInstallParameterReachesEveryCapability(t *testing.T) {
	const collection = "http://radicale/owner/work/"
	rec := integrations.Recipe{
		Name: "fake-cfg",
		Capabilities: map[string]integrations.Binding{
			"check_availability": {
				Tool: "list-events", Kind: "freebusy",
				Args: map[string]string{"calendarUrl": "$cfg.calendar_url",
					"start": "$window_start", "end": "$window_end"},
				Out: map[string]string{"busy": "", "busy_start": "start", "busy_end": "end"},
			},
			"book_slot": {
				Tool: "create-event", Kind: "create",
				Args: map[string]string{"calendarUrl": "$cfg.calendar_url",
					"summary": "$subject", "start": "$start", "end": "$end"},
				Out: map[string]string{"event_id": ""},
			},
			"cancel_booking": {
				Tool: "delete-event", Kind: "delete",
				Args: map[string]string{"calendarUrl": "$cfg.calendar_url", "uid": "$event_id"},
			},
		},
	}
	seen := map[string]any{}
	cal := &Calendar{
		Recipe: rec, Store: idemStore(t), Account: "acct",
		Params: map[string]string{"calendar_url": collection},
		Call: func(_ context.Context, tool string, args map[string]any) (any, error) {
			seen[tool] = args["calendarUrl"]
			switch tool {
			case "list-events":
				return []any{}, nil
			case "create-event":
				return "uid-1", nil // plain text, as caldav-mcp answers (E15)
			}
			return map[string]any{}, nil
		},
	}
	ctx := context.Background()
	if _, err := cal.CheckAvailability(ctx, day.Add(9*time.Hour), day.Add(17*time.Hour), 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	ack, err := cal.BookSlot(ctx, "sha256:c", "msg-1",
		Slot{Start: day.Add(10 * time.Hour), End: day.Add(10*time.Hour + 30*time.Minute)}, "Tea")
	if err != nil {
		t.Fatal(err)
	}
	// The plain-text uid must survive as the booking id, or E15's fix is cosmetic.
	if ack.BookingID == "" {
		t.Error("a plain-text event id did not become a booking id")
	}
	if err := cal.CancelBooking(ctx, ack.BookingID); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"list-events", "create-event", "delete-event"} {
		if seen[tool] != collection {
			t.Errorf("%s was called with calendarUrl=%v, want %q — the install's "+
				"parameter did not reach it", tool, seen[tool], collection)
		}
	}
}

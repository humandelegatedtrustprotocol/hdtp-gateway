// Package providers implements PACT core capabilities over upstream tools
// through recipes (SPEC §6.7). Contacts see PACT's vocabulary — never a
// vendor's. All computation (slot math, policy filtering, ICS synthesis)
// lives HERE, in code; recipes only line fields up.
package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	ics "github.com/arran4/golang-ical"

	"github.com/tech-sumit/pact-gateway/internal/integrations"
)

// MaxSlots is PACT §12's cap: never more than 5 candidate slots.
const MaxSlots = 5

// Caller invokes one upstream tool and returns its decoded JSON result.
type Caller func(ctx context.Context, tool string, args map[string]any) (any, error)

// IdemStore is the §11.2 idempotency slice the booking path needs.
type IdemStore interface {
	PutIdempotency(ctx context.Context, accountID, contactFpr, msgID, ack string, expiresAt int64) (string, bool, error)
}

// Slot is one candidate interval (RFC 3339 on the wire).
type Slot struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Policy is the owner's availability policy: allowed weekdays and working
// hours (minutes since local midnight). Zero value = Mon–Fri 09:00–17:00.
type Policy struct {
	Workdays  map[time.Weekday]bool
	WorkStart int
	WorkEnd   int
}

func (p Policy) normalized() Policy {
	if p.Workdays == nil {
		p.Workdays = map[time.Weekday]bool{
			time.Monday: true, time.Tuesday: true, time.Wednesday: true,
			time.Thursday: true, time.Friday: true,
		}
	}
	if p.WorkStart == 0 && p.WorkEnd == 0 {
		p.WorkStart, p.WorkEnd = 9*60, 17*60
	}
	return p
}

// allows reports whether a slot sits fully inside working hours on a workday.
func (p Policy) allows(s Slot) bool {
	p = p.normalized()
	if !p.Workdays[s.Start.Weekday()] || !s.End.After(s.Start) {
		return false
	}
	startMin := s.Start.Hour()*60 + s.Start.Minute()
	endMin := s.End.Hour()*60 + s.End.Minute()
	if s.End.Day() != s.Start.Day() {
		return false
	}
	return startMin >= p.WorkStart && endMin <= p.WorkEnd
}

// Calendar implements check_availability / book_slot / cancel_booking
// (PACT §6.2) over one recipe.
type Calendar struct {
	Call    Caller
	Recipe  integrations.Recipe
	Policy  Policy
	Store   IdemStore
	Account string
	// Params are this INSTALL's recipe parameters, referenced from a recipe as
	// `$cfg.<name>`. Some upstreams need a value only the install knows — a CalDAV
	// collection URL, a calendar id — and the mapping DSL has only field
	// references and constants, so without these a recipe for such a server
	// cannot be written at all. Google's servers never needed one because they
	// default to the primary calendar, which is why this surfaced late.
	Params map[string]string
	Now    func() time.Time
}

// fields merges the install's parameters into the provider's own under a `cfg.`
// namespace. The namespace is what makes it unambiguous: no provider field name
// contains a dot, so a parameter can never shadow `$start` or `$subject`.
func (c *Calendar) fields(own map[string]any) map[string]any {
	for k, v := range c.Params {
		own["cfg."+k] = v
	}
	return own
}

// CheckAvailability returns ≤5 policy-filtered candidate slots — never raw
// free/busy (SPEC §6.7).
func (c *Calendar) CheckAvailability(ctx context.Context, windowStart, windowEnd time.Time, duration time.Duration) ([]Slot, error) {
	b, ok := c.Recipe.Capabilities["check_availability"]
	if !ok {
		return nil, fmt.Errorf("providers: recipe %s has no check_availability", c.Recipe.Name)
	}
	args, err := integrations.BuildArgs(b, c.fields(map[string]any{
		"window_start":     windowStart.Format(time.RFC3339),
		"window_end":       windowEnd.Format(time.RFC3339),
		"duration_minutes": int(duration / time.Minute),
	}))
	if err != nil {
		return nil, err
	}
	res, err := c.Call(ctx, b.Tool, args)
	if err != nil {
		return nil, err
	}
	var candidates []Slot
	switch b.Kind {
	case "suggest":
		candidates, err = c.slotsFromSuggestions(b, res, duration)
	case "freebusy":
		candidates, err = c.slotsFromBusy(b, res, windowStart, windowEnd, duration)
	default:
		return nil, fmt.Errorf("providers: unknown availability kind %q", b.Kind)
	}
	if err != nil {
		return nil, err
	}
	out := candidates[:0]
	for _, s := range candidates {
		if c.Policy.allows(s) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	if len(out) > MaxSlots {
		out = out[:MaxSlots]
	}
	return out, nil
}

func (c *Calendar) slotsFromSuggestions(b integrations.Binding, res any, d time.Duration) ([]Slot, error) {
	list, ok := integrations.Lookup(res, b.Out["slots"])
	if !ok {
		return nil, fmt.Errorf("providers: response misses %q", b.Out["slots"])
	}
	items, ok := list.([]any)
	if !ok {
		return nil, fmt.Errorf("providers: %q is not a list", b.Out["slots"])
	}
	startKey, endKey := b.Out["slot_start"], b.Out["slot_end"]
	if startKey == "" {
		startKey = "start"
	}
	var out []Slot
	for _, it := range items {
		startStr, ok := integrations.LookupString(it, startKey)
		if !ok {
			continue
		}
		start, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			continue
		}
		end := start.Add(d)
		if endKey != "" {
			if endStr, ok := integrations.LookupString(it, endKey); ok {
				if e, err := time.Parse(time.RFC3339, endStr); err == nil {
					end = e
				}
			}
		}
		out = append(out, Slot{Start: start, End: end})
	}
	return out, nil
}

// slotsFromBusy computes duration-sized candidates inside the window that miss
// every busy block: the raw free/busy NEVER leaves the provider.
func (c *Calendar) slotsFromBusy(b integrations.Binding, res any, winStart, winEnd time.Time, d time.Duration) ([]Slot, error) {
	list, ok := integrations.Lookup(res, b.Out["busy"])
	if !ok {
		return nil, fmt.Errorf("providers: response misses %q", b.Out["busy"])
	}
	items, _ := list.([]any)
	startKey, endKey := b.Out["busy_start"], b.Out["busy_end"]
	if startKey == "" {
		startKey = "start"
	}
	if endKey == "" {
		endKey = "end"
	}
	type span struct{ s, e time.Time }
	var busy []span
	for _, it := range items {
		ss, ok1 := integrations.LookupString(it, startKey)
		es, ok2 := integrations.LookupString(it, endKey)
		if !ok1 || !ok2 {
			continue
		}
		s, err1 := time.Parse(time.RFC3339, ss)
		e, err2 := time.Parse(time.RFC3339, es)
		if err1 != nil || err2 != nil {
			continue
		}
		busy = append(busy, span{s, e})
	}
	var out []Slot
	for t := winStart; !t.Add(d).After(winEnd); t = t.Add(d) {
		cand := Slot{Start: t, End: t.Add(d)}
		clear := true
		for _, bz := range busy {
			if cand.Start.Before(bz.e) && bz.s.Before(cand.End) {
				clear = false
				break
			}
		}
		if clear {
			out = append(out, cand)
		}
	}
	return out, nil
}

// BookingAck is the recorded acknowledgment (§11.2) book_slot returns.
type BookingAck struct {
	BookingID string `json:"booking_id"`
	ICS       string `json:"ics"`
}

// BookSlot creates the event upstream, idempotently by msg_id: a replay returns
// the recorded acknowledgment without re-executing (SPEC §6.7).
func (c *Calendar) BookSlot(ctx context.Context, contactFpr, msgID string, slot Slot, subject string) (BookingAck, error) {
	b, ok := c.Recipe.Capabilities["book_slot"]
	if !ok {
		return BookingAck{}, fmt.Errorf("providers: recipe %s has no book_slot", c.Recipe.Name)
	}
	args, err := integrations.BuildArgs(b, c.fields(map[string]any{
		"start":   slot.Start.Format(time.RFC3339),
		"end":     slot.End.Format(time.RFC3339),
		"subject": subject,
	}))
	if err != nil {
		return BookingAck{}, err
	}
	// idempotency FIRST: reserve the msg_id; a loser returns the winner's ack.
	probe, existed, err := c.Store.PutIdempotency(ctx, c.Account, contactFpr, msgID, "", 0)
	if err != nil {
		return BookingAck{}, err
	}
	if existed {
		var ack BookingAck
		if probe == "" {
			return BookingAck{}, fmt.Errorf("providers: booking %s is still in flight", msgID)
		}
		if err := json.Unmarshal([]byte(probe), &ack); err != nil {
			return BookingAck{}, fmt.Errorf("providers: %w", err)
		}
		return ack, nil
	}
	res, err := c.Call(ctx, b.Tool, args)
	if err != nil {
		return BookingAck{}, err
	}
	eventID, ok := integrations.LookupString(res, b.Out["event_id"])
	if !ok || eventID == "" {
		return BookingAck{}, fmt.Errorf("providers: upstream returned no event id at %q", b.Out["event_id"])
	}
	ack := BookingAck{
		BookingID: EncodeBookingID(eventID),
		ICS:       c.synthesizeICS(eventID, slot, subject),
	}
	blob, _ := json.Marshal(ack)
	// second Put upgrades the reservation to the real ack (first-writer row
	// already exists; overwrite via fresh key is impossible, so store the ack
	// under the same key by writing again only when the reservation was ours)
	if err := c.finalizeAck(ctx, contactFpr, msgID, string(blob)); err != nil {
		return BookingAck{}, err
	}
	return ack, nil
}

// finalizeAck replaces the in-flight reservation with the recorded ack.
func (c *Calendar) finalizeAck(ctx context.Context, contactFpr, msgID, ack string) error {
	type upd interface {
		UpdateIdempotencyAck(ctx context.Context, accountID, contactFpr, msgID, ack string) error
	}
	if u, ok := c.Store.(upd); ok {
		return u.UpdateIdempotencyAck(ctx, c.Account, contactFpr, msgID, ack)
	}
	return fmt.Errorf("providers: store cannot finalize acknowledgments")
}

// EncodeBookingID wraps the upstream event identifier opaquely (SPEC §6.7).
func EncodeBookingID(eventID string) string {
	return "bk_" + base64.RawURLEncoding.EncodeToString([]byte(eventID))
}

// DecodeBookingID maps a booking_id back to the upstream event identifier.
func DecodeBookingID(bookingID string) (string, error) {
	raw, ok := strings.CutPrefix(bookingID, "bk_")
	if !ok {
		return "", fmt.Errorf("providers: not a booking id")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("providers: bad booking id")
	}
	return string(b), nil
}

func (c *Calendar) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// synthesizeICS builds the confirmation ICS from the confirmed slot + subject
// (the provider synthesizes it; no upstream ICS is trusted — SPEC §6.7).
func (c *Calendar) synthesizeICS(eventID string, slot Slot, subject string) string {
	cal := ics.NewCalendar()
	cal.SetMethod(ics.MethodRequest)
	ev := cal.AddEvent(eventID + "@pact-gateway")
	ev.SetCreatedTime(c.now())
	ev.SetDtStampTime(c.now())
	ev.SetStartAt(slot.Start)
	ev.SetEndAt(slot.End)
	ev.SetSummary(subject)
	return cal.Serialize()
}

// CancelBooking maps the booking_id back and deletes the upstream event.
func (c *Calendar) CancelBooking(ctx context.Context, bookingID string) error {
	b, ok := c.Recipe.Capabilities["cancel_booking"]
	if !ok {
		return fmt.Errorf("providers: recipe %s has no cancel_booking", c.Recipe.Name)
	}
	eventID, err := DecodeBookingID(bookingID)
	if err != nil {
		return err
	}
	args, err := integrations.BuildArgs(b, c.fields(map[string]any{"event_id": eventID}))
	if err != nil {
		return err
	}
	_, err = c.Call(ctx, b.Tool, args)
	return err
}

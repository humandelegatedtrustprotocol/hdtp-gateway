// Package calendar holds what a calendar provider and the public surface exchange (HDTP §6.2): a
// candidate interval, a booking's acknowledgment, and the cap on how many candidates are offered.
// The public surface names the port (public.Calendar); the provider (integrations/providers)
// implements it; neither imports the other.
package calendar

import "time"

// MaxSlots is HDTP §12's cap: never more than 5 candidate slots.
const MaxSlots = 5

// Slot is one candidate interval (RFC 3339 on the wire).
type Slot struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// BookingAck is the recorded acknowledgment (§11.2) book_slot returns.
type BookingAck struct {
	BookingID string `json:"booking_id"`
	ICS       string `json:"ics"`
}

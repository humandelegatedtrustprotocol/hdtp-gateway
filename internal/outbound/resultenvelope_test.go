package outbound

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/envelope"
)

// A peer's sealed answer is an envelope of exactly `protected`, `enc`, `ct` and `sig`, each a string,
// by name byte for byte (HDTP §13.1, SEP-0005). Any other is refused as it is decoded,
// envelope_invalid, before OpenResult: it is not taken for an answer signed by a leaf this caller
// does not hold, so no get_card of either kind is asked. The answers carry the renewed chain, so
// the control, the same answer unaltered, verifies. Shown red on 0.8.2, which read a fifth member
// past and "SIG" as `sig` and delivered, and read an absent or null `sig` as empty and went on to
// get_card.
func TestAMalformedResultEnvelopeIsEnvelopeInvalidAndAsksNoCard(t *testing.T) {
	for name, mangle := range map[string]func(string) string{
		"a fifth member":           func(s string) string { return strings.Replace(s, `{`, `{"note":"x",`, 1) },
		"a member spelled in caps": func(s string) string { return strings.Replace(s, `"sig":`, `"SIG":`, 1) },
		"sig absent": func(s string) string {
			i := strings.Index(s, `,"sig":`)
			return s[:i] + "}"
		},
		"sig null": func(s string) string {
			i := strings.Index(s, `"sig":`)
			return s[:i] + `"sig":null}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
			bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
			p := startRenewedPeer(t, alina, bharat)
			p.form = "chain"
			p.mangle = mangle
			var repinned [][]byte
			c := callerTo(t, bharat, p, &repinned)
			_, err := c.SealedCall(context.Background(), p.peer("optional"), "send_message", map[string]any{"text": "hi"}, "m-mangled")
			if !errors.Is(err, envelope.ErrInvalid) {
				t.Fatalf("answered %v, want envelope_invalid", err)
			}
			if p.calls["get_card"] != 0 || p.calls["sealed get_card"] != 0 || p.calls["sealed_call"] != 1 {
				t.Fatalf("calls %v, want one sealed_call and no get_card of either kind", p.calls)
			}
			if len(repinned) != 0 {
				t.Fatalf("an answer refused as it is decoded moves no pin: %d re-pin(s)", len(repinned))
			}
		})
	}
	alina := newTestIdentity(t, "Alina", "https://agent.alina.example/mcp")
	bharat := newTestIdentity(t, "Bharat", "https://agent.bharat.example/mcp")
	p := startRenewedPeer(t, alina, bharat)
	p.form = "chain"
	p.mangle = func(s string) string { return s }
	var repinned [][]byte
	res, err := callerTo(t, bharat, p, &repinned).SealedCall(context.Background(), p.peer("optional"), "send_message", map[string]any{"text": "hi"}, "m-control")
	if err != nil {
		t.Fatalf("the control, the same answer unaltered, must verify: %v", err)
	}
	delivered(t, res)
}

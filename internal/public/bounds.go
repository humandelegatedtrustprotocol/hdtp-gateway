package public

// Boundary limits of SPEC §5.7 that the listener enforces itself — the body cap, before anything
// parses a request — and the `limits` get_card advertises (HDTP §12). The call budgets are not
// decided here: the limits sidecar decides them (internal/limits, cmd/hdtp-limitd), and the node
// asks it for every call (node.consumeBudget).

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/calendar"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/limits"
)

// AuditFn receives boundary events; wired to the audit chain by serve (SPEC
// §11.5). Three fields, like the chain itself: the resource locates what was
// touched, the outcome is the verdict alone.
type AuditFn func(action, resource, outcome string)

// WHERE THE BUDGET IS SPENT. HDTP §12 budgets CALLS, and a call is not an HTTP request: an MCP
// client sends `server/discover` or the handshake before it calls, and a limiter at the HTTP layer
// once spent a guest's whole hourly budget before it asked for anything. So the budget is spent in
// the dispatch path (Pool.guarded, and the sealed handler for the inner call), and a refusal is a
// `rate_limited` tool error, which is what a caller's agent can act on.

// CapBody refuses a request body past maxBytes, counted by the bytes that arrive rather than by the
// length the request declares, with 413 and HDTP's `too_large` (SPEC §5.7), before anything parses
// it; a body within the cap is handed on whole. It used to wrap the body in a MaxBytesReader and
// leave the answer to whatever read it — which, behind the MCP SDK, was the SDK's own plaintext 413,
// at the SDK's own default of 4 MiB, under this cap: the 8 MiB SPEC §5.7 sizes for 5 MiB of inline
// media was never what the listener took (TestBodyCap held a stub reader, not the listener).
func CapBody(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > maxBytes {
			tooLarge(w)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		if err != nil {
			http.Error(w, "the request body could not be read", http.StatusBadRequest)
			return
		}
		if int64(len(b)) > maxBytes {
			tooLarge(w)
			return
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		next.ServeHTTP(w, r)
	})
}

func tooLarge(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_, _ = w.Write([]byte(`{"code":"too_large"}`))
}

// Limits is the boundary metadata get_card advertises (HDTP §12): the values in force on this node,
// so a peer can discover an operator-tuned budget instead of finding out from too_large or
// rate_limited. Members are stable wire contract — the spec names them. The call budgets are
// numbers, not counts: a configuration may set a contact's rate below one call a second.
type Limits struct {
	// TextBytes is MaxTextBytes: the cap on a message's text.
	TextBytes int `json:"text_bytes"`
	// NoteBytes is MaxNoteBytes: the cap on a request note.
	NoteBytes int `json:"note_bytes"`
	// MediaInlineBytes is MaxInlineData: the cap on decoded inline media.
	MediaInlineBytes int `json:"media_inline_bytes"`
	// AvailabilitySlots is calendar.MaxSlots: the most slots one answer carries.
	AvailabilitySlots int `json:"availability_slots"`
	// InviteTTLDays is contacts.MaxInviteTTL in whole days.
	InviteTTLDays int `json:"invite_ttl_days"`
	// Advertised (embedded) carries the call-budget members, as the limits sidecar computes them.
	limits.Advertised
}

// LimitsWith is what an account advertises: every size from the constant that enforces it, and the
// call budgets as the limits sidecar that enforces them computes them for the account.
func LimitsWith(calls limits.Advertised) Limits {
	return Limits{
		TextBytes:         MaxTextBytes,
		NoteBytes:         MaxNoteBytes,
		MediaInlineBytes:  MaxInlineData,
		AvailabilitySlots: calendar.MaxSlots,
		InviteTTLDays:     int(contacts.MaxInviteTTL / (24 * time.Hour)),
		Advertised:        calls,
	}
}

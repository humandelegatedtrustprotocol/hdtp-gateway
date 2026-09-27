// Package auditsink is the node's one writer of the audit chain as the surfaces see it: a
// three-argument function per actor kind, which appends to the hash chain (SPEC §11) and mirrors
// each row to the log.
package auditsink

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pact-cloud/pact-gateway/internal/core/audit"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// New turns the hash-chain writer into the three-argument sink every
// surface takes. A failed audit write is reported, never swallowed silently:
// SPEC §11 forbids responding without one, and losing the chain is the kind of
// failure an operator must see.
func New(ctx context.Context, st store.AuditStore, stderr io.Writer) *Sink {
	// A container's log IS its operating surface, and this node printed six lines
	// of banner and then nothing: an owner watching `docker logs` had no way to
	// see a refusal, an approval, or a failed delivery, and the audit CLI cannot
	// read the chain while the node holds the data directory. So every event is
	// mirrored to stderr as it is written.
	//
	// It mirrors the audit row and nothing else, which is what makes it safe: the
	// chain records the KEY of a setting and never its value, fingerprints rather
	// than names, and content-addressed references rather than bodies. Nothing
	// leaves the machine — `PACT_LOG=off` silences it for anyone who wants that.
	return &Sink{w: &audit.Writer{Sink: st}, ctx: ctx, stderr: stderr,
		mirror: os.Getenv("PACT_LOG") != "off"}
}

// Sink writes to the one hash chain, tagging each event with WHO caused it.
// The actor kind is not decoration: the audit page filters on it, and a chain
// that records "a peer changed this node's seal policy" cannot answer the
// question an operator actually asks — what did I do, and what was done to me.
type Sink struct {
	w      *audit.Writer
	ctx    context.Context
	stderr io.Writer
	mirror bool
}

func (a *Sink) as(kind string) func(action, resource, outcome string) {
	// Recover the account the same way the kinded path does. Only that path
	// used to do it, and almost nothing goes through it: every row the public
	// tool surface writes — messages, media, bookings, the traffic that is
	// actually about somebody — was landing with an empty account, which made
	// both §11.6's token scoping and the portal's account scoping vacuous.
	return func(action, resource, outcome string) {
		a.forAccount(accountFromResource(resource), kind)(action, resource, outcome)
	}
}

// forAccount is `as` with the account the event belongs to.
//
// Every row used to be written with an empty account, which made §11.6's
// per-account audit scoping vacuous: `audit_query` permitted a row when it had
// no account, and no row ever had one, so a token narrowed to a single account
// read the whole node's chain. The column is the filter, so it has to be filled
// wherever the account is known.
func (a *Sink) forAccount(accountID, kind string) func(action, resource, outcome string) {
	return func(action, resource, outcome string) {
		if err := a.w.Append(a.ctx, accountID, kind, "", action, resource, outcome, "", ""); err != nil {
			fmt.Fprintf(a.stderr, "audit: %s %s %s: %v\n", action, resource, outcome, err)
			return
		}
		if a.mirror {
			if resource == "" {
				fmt.Fprintf(a.stderr, "%s %s %s\n", kind, action, outcome)
				return
			}
			fmt.Fprintf(a.stderr, "%s %s %s %s\n", kind, action, resource, outcome)
		}
	}
}

// System: the node's own lifecycle — listeners, adapters, refusals not tied to
// a resolved caller. The vocabulary is the store's (`owner`, `token`, `contact`,
// `guest`, `cli`, `system`); anything outside it is rejected by the schema, so
// this is deliberately not free-form.
func (a *Sink) System() func(action, resource, outcome string) { return a.as("system") }

// Kinded lets a caller name the actor per event. Unknown kinds fall back to
// `system` rather than being written: the store rejects anything outside its
// vocabulary, and a rejected write is a hole in the chain.
func (a *Sink) Kinded() func(kind, action, resource, outcome string) {
	allowed := map[string]bool{
		"owner": true, "token": true, "contact": true, "guest": true, "cli": true, "system": true,
	}
	return func(kind, action, resource, outcome string) {
		if !allowed[kind] {
			kind = "system"
		}
		a.as(kind)(action, resource, outcome)
	}
}

// Owner: everything reached through the portal or the owner MCP.
func (a *Sink) Owner() func(action, resource, outcome string) { return a.as("owner") }

// accountFromResource recovers the account id the node prefixes into a resource
// string (`account:<id> …`). It is a recovery rather than a redesign: the
// prefix already carries the fact, and threading a second parameter through
// every audit call site would touch far more code than the filter needs.
func accountFromResource(resource string) string {
	const prefix = "account:"
	if !strings.HasPrefix(resource, prefix) {
		return ""
	}
	rest := resource[len(prefix):]
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		return rest[:i]
	}
	return rest
}

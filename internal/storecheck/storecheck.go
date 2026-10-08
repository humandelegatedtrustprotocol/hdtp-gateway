// Package storecheck reads every card and certificate the store holds by the rule the identity
// core reads them with, and names each that does not read. It changes nothing.
//
// Why it exists: the core's reading gets stricter (the identity core 0.4.2's DecodeB64url refuses a
// character outside the base64url alphabet that 0.4.1 skipped), and what a node accepted at intake
// under the old reading is still on file after the bump. The core then refuses it where it reads
// it — a contact's card in `contacts.SealOf`, so `node.PeerOf` refuses to write to that contact; a
// pin's leaf in Decide's `pinHolding`, so a call naming it is refused as this node's unreadable
// state — with nothing to say which row, until somebody calls. This is the walk that says it
// first: `serve` prints it in its banner, and `hdtp-gateway check store` exits 1 on it
// (docs/release/port-parity-2026-09-29.md, P4).
//
// One reading per field, the node's own: a card is read by contacts.SealOf, the reader every write
// to a contact goes through; a certificate held as DER is read by hdtpidentity.Parse, the reader
// the core applies to it once the node has encoded it for Decide. The fields are every column that
// holds a certificate or a card: the account's root, its leaves,
// each contact's card, leaf and root certificate, each tombstone's leaf, each pending address's
// leaf and root certificate. Invites, pending requests and messages hold none.
//
// The same walk counts each contact whose status is one this node does not know — neither a state
// a pin has nor a request awaiting the owner (public.UnknownContactState) — and names its row. The
// node hands the identity core no pin for such a row (public/decide.go, pinsOf), where the core
// would refuse the state as unreadable and the owner would be told on the call; the schema admits
// no such row, so one is a hand-edited store's or a later binary's, and this walk
// is where the owner hears of it.
package storecheck

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/public"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// Refusal is one stored field the core's reader refuses: the table and field it is in, what names
// its row to the owner, and the reader's reason.
type Refusal struct {
	Table string // accounts | leaves | contacts | tombstones | pending_addresses
	Row   string // account:<slug>, then what tells the row apart: contact:<root>, kid:<kid>, root:<root>
	Field string // root_cert | leaf | card
	// Why is the reader's reason: the error of contacts.SealOf for a card, `certificate does not
	// parse: ` and the error of hdtpidentity.Parse for a certificate.
	Why string
}

// NoPin is one contact row the node hands the identity core no pin for because its status is one
// this node does not know (public.UnknownContactState): what names its row, and the status found.
type NoPin struct {
	Row string // account:<slug> contact:<root>
	// Status is the status the row holds.
	Status string
}

// Report is what a run read, what it refused, and the contact rows in a state it does not know.
type Report struct {
	// Read counts the fields read, by `<table>.<field>`: a contact holding a card, a leaf and a root
	// certificate counts once under each.
	Read map[string]int
	// Refusals is every field the core's reader refused, in the order the walk met them.
	Refusals []Refusal
	// NoPin is every contact whose status is neither a state a pin has nor `pending_in`, in the
	// order the store lists them.
	NoPin []NoPin
}

// Fields is how many fields were read.
func (r Report) Fields() int {
	n := 0
	for _, c := range r.Read {
		n += c
	}
	return n
}

// Lines is the report as an operator reads it, and both doors print the same lines: the banner's
// `store:` line — what was read, by field, how many did not, and how many contacts are in a state
// neither a pin nor a request has (that clause only when there is one) — then one `NOT READ` line
// per refusal, naming the table, the row and the field before the reader's reason, then one
// `NO PIN` line per contact in a state this node does not know, naming the row and the status.
func (r Report) Lines() []string {
	keys := make([]string, 0, len(r.Read))
	for k := range r.Read {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, r.Read[k]))
	}
	by := "none held"
	if len(parts) > 0 {
		by = strings.Join(parts, ", ")
	}
	verdict := "all read"
	switch n := len(r.Refusals); {
	case n == 1:
		verdict = "1 does NOT read"
	case n > 1:
		verdict = fmt.Sprintf("%d do NOT read", n)
	}
	summary := fmt.Sprintf("store:   %d cards and certificates read by the identity core's rule (%s); %s", r.Fields(), by, verdict)
	switch n := len(r.NoPin); {
	case n == 1:
		summary += "; 1 contact in a state neither a pin nor a request has"
	case n > 1:
		summary += fmt.Sprintf("; %d contacts in a state neither a pin nor a request has", n)
	}
	lines := []string{summary}
	for _, f := range r.Refusals {
		lines = append(lines, fmt.Sprintf("NOT READ %s %s %s: %s", f.Table, f.Row, f.Field, f.Why))
	}
	for _, p := range r.NoPin {
		lines = append(lines, fmt.Sprintf("NO PIN contacts %s status: %q is neither a state a pin has (active, pending_out, blocked) nor a request awaiting the owner (pending_in); the identity core is handed no pin for this row", p.Row, p.Status))
	}
	return lines
}

// Run reads every card and certificate the store holds, account by account, and reports. A store
// that cannot be listed is an error, not a refusal: the report says what was read, and nothing
// was when it could not be.
func Run(ctx context.Context, st store.Store, now time.Time) (Report, error) {
	r := Report{Read: map[string]int{}}
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, a := range accts {
		row := "account:" + a.Slug
		r.der("accounts", row, "root_cert", a.RootCert)
		leaves, err := st.ListLeaves(ctx, a.ID)
		if err != nil {
			return Report{}, err
		}
		for _, l := range leaves {
			r.der("leaves", row+" kid:"+l.Kid, "leaf", l.Leaf)
		}
		cs, err := st.ListContacts(ctx, a.ID)
		if err != nil {
			return Report{}, err
		}
		for _, c := range cs {
			crow := row + " contact:" + c.Fingerprint
			r.card(crow, c.Card, now)
			r.der("contacts", crow, "leaf", c.Leaf)
			r.der("contacts", crow, "root_cert", c.RootCert)
			r.state(crow, c.Status)
		}
		tombs, err := st.ListTombstones(ctx, a.ID)
		if err != nil {
			return Report{}, err
		}
		for _, t := range tombs {
			r.der("tombstones", row+" root:"+t.Root, "leaf", t.Leaf)
		}
		pending, err := st.ListPendingAddresses(ctx, a.ID)
		if err != nil {
			return Report{}, err
		}
		for _, p := range pending {
			prow := row + " root:" + p.Root
			r.der("pending_addresses", prow, "leaf", p.Leaf)
			r.der("pending_addresses", prow, "root_cert", p.RootCert)
		}
	}
	return r, nil
}

// card reads a contact's card as every write to that contact reads it (contacts.SealOf: the core's
// DecodeCard, its certificate by DecodeB64url). An empty card is a contact written without one —
// an import, or a root re-added from a pending address — and is not a field to read.
func (r *Report) card(row, card string, now time.Time) {
	if card == "" {
		return
	}
	r.Read["contacts.card"]++
	if _, err := contacts.SealOf(card, now); err != nil {
		r.Refusals = append(r.Refusals, Refusal{Table: "contacts", Row: row, Field: "card", Why: err.Error()})
	}
}

// state notes a contact whose status is one this node does not know, by the one reading pinsOf
// applies (public.UnknownContactState): the node hands the identity core no pin for the row.
func (r *Report) state(row, status string) {
	if !public.UnknownContactState(status) {
		return
	}
	r.NoPin = append(r.NoPin, NoPin{Row: row, Status: status})
}

// der reads a certificate held as DER as the core reads it (hdtpidentity.Parse). An empty column
// is a row that holds none — a pin made over a sealed call never saw its root's certificate, an
// account not yet certified has no root — and is not a field to read.
func (r *Report) der(table, row, field string, der []byte) {
	if len(der) == 0 {
		return
	}
	r.Read[table+"."+field]++
	if _, err := hdtpidentity.Parse(der); err != nil {
		r.Refusals = append(r.Refusals, Refusal{Table: table, Row: row, Field: field, Why: "certificate does not parse: " + err.Error()})
	}
}

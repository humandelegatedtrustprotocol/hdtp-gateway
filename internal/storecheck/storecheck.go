// Package storecheck reads every card and certificate the store holds by the rule the identity
// core reads them with, and names each that does not read. It changes nothing.
//
// Why it exists: the core's reading gets stricter (pact-identity 0.4.2's DecodeB64url refuses a
// character outside the base64url alphabet that 0.4.1 skipped), and what a node accepted at intake
// under the old reading is still on file after the bump. The core then refuses it where it reads
// it — a contact's card in `contacts.SealOf`, so `node.PeerOf` refuses to write to that contact; a
// pin's leaf in Decide's `pinHolding`, so a call naming it is refused as this node's unreadable
// state — with nothing to say which row, until somebody calls. This is the walk that says it
// first: `serve` prints it in its banner, and `pact-gateway check store` exits 1 on it
// (docs/release/port-parity-2026-09-29.md, P4).
//
// One reading per field, the node's own: a card is read by contacts.SealOf, the reader every write
// to a contact goes through; a certificate held as DER is read by pactidentity.Parse, the reader
// the core applies to it once the node has encoded it for Decide. The fields are every column that
// holds a certificate or a card (migrations 0002, 0027, 0029): the account's root, its leaves,
// each contact's card, leaf and root certificate, each tombstone's leaf, each pending address's
// leaf and root certificate. Invites, pending requests and messages hold none.
package storecheck

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// Refusal is one stored field the core's reader refuses: the table and field it is in, what names
// its row to the owner, and the reader's reason.
type Refusal struct {
	Table string // accounts | leaves | contacts | tombstones | pending_addresses
	Row   string // account:<slug>, then what tells the row apart: contact:<root>, kid:<kid>, root:<root>
	Field string // root_cert | leaf | card
	Why   string
}

// Report is what a run read and what it refused.
type Report struct {
	// Read counts the fields read, by `<table>.<field>`: a contact holding a card, a leaf and a root
	// certificate counts once under each.
	Read     map[string]int
	Refusals []Refusal
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
// `store:` line — what was read, by field, and how many did not — then one `NOT READ` line per
// refusal, naming the table, the row and the field before the reader's reason.
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
	lines := []string{fmt.Sprintf("store:   %d cards and certificates read by the identity core's rule (%s); %s", r.Fields(), by, verdict)}
	for _, f := range r.Refusals {
		lines = append(lines, fmt.Sprintf("NOT READ %s %s %s: %s", f.Table, f.Row, f.Field, f.Why))
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

// der reads a certificate held as DER as the core reads it (pactidentity.Parse). An empty column
// is a row that holds none — a pin made before migration 0029 kept no root certificate, an
// account not yet certified has no root — and is not a field to read.
func (r *Report) der(table, row, field string, der []byte) {
	if len(der) == 0 {
		return
	}
	r.Read[table+"."+field]++
	if _, err := pactidentity.Parse(der); err != nil {
		r.Refusals = append(r.Refusals, Refusal{Table: table, Row: row, Field: field, Why: "certificate does not parse: " + err.Error()})
	}
}

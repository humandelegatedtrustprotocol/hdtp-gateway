package contacts

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// SPEC §9.1 draws the contact lifecycle as a mermaid state diagram, and the diagram said a
// rejection deletes the request (`pending_in --> none : owner rejects`) for as long as the code
// demoted it to blocked (review N-04). A drawing nothing reads goes stale silently, so this reads it
// and holds it to the code in two ways:
//
//   - its states are exactly `none` and the statuses the contacts table admits (the CHECK
//     constraint of the newest migration that declares one);
//   - every edge out of a stored state is the outcome of running the action it names. Each case
//     below seeds a row, runs the real Owner or Manager method on a real store, reads back what
//     is left, and the diagram must carry an edge from the seeded state to that result whose
//     label names the action; and every edge out of a stored state must be reached by a case.
//
// The edges out of `none` — an invite redeemed, a request sent — are not run here: they are the
// redemption paths, held by the manager's own tests. Only their states are checked.
func TestSpecLifecycleDiagramIsWhatTheCodeDoes(t *testing.T) {
	edges := specLifecycleEdges(t)

	states := map[string]bool{}
	for _, e := range edges {
		for _, s := range []string{e.from, e.to} {
			if s != "[*]" {
				states[s] = true
			}
		}
	}
	want := map[string]bool{"none": true}
	for _, s := range contactStatusesAdmitted(t) {
		want[s] = true
	}
	if a, b := keys(states), keys(want); strings.Join(a, " ") != strings.Join(b, " ") {
		t.Fatalf("SPEC §9.1's diagram has states %v; the contacts table admits %v (plus none)", a, b)
	}

	type action struct {
		from, label string
		everActive  bool
		run         func(ctx context.Context, e *env, o Owner, g *guestID, card string) error
	}
	approve := func(ctx context.Context, e *env, o Owner, g *guestID, _ string) error {
		_, err := o.Approve(ctx, e.account, g.Fingerprint, "")
		return err
	}
	reject := func(ctx context.Context, e *env, o Owner, g *guestID, _ string) error {
		_, err := o.Reject(ctx, e.account, g.Fingerprint)
		return err
	}
	remove := func(ctx context.Context, e *env, o Owner, g *guestID, _ string) error {
		_, err := o.Remove(ctx, e.account, g.Fingerprint)
		return err
	}
	block := func(ctx context.Context, e *env, o Owner, g *guestID, _ string) error {
		_, err := o.Block(ctx, e.account, g.Fingerprint)
		return err
	}
	unblock := func(ctx context.Context, e *env, o Owner, g *guestID, _ string) error {
		_, err := o.Unblock(ctx, e.account, g.Fingerprint)
		return err
	}
	expire := func(ctx context.Context, e *env, o Owner, g *guestID, _ string) error {
		*e.clock = e.clock.Add(DefaultRequestExpiry + time.Hour)
		_, err := o.ExpireRequests(ctx, e.account, 0)
		return err
	}
	cases := []action{
		{from: "pending_in", label: "owner approves", run: approve},
		{from: "pending_in", label: "owner rejects", run: reject},
		{from: "pending_in", label: "owner removes", run: remove},
		{from: "pending_in", label: "request expires", run: expire},
		{from: "pending_out", label: "peer approves", run: func(ctx context.Context, e *env, _ Owner, g *guestID, card string) error {
			return e.m.ContactAccepted(ctx, e.account, g.Fingerprint, card, nil)
		}},
		{from: "pending_out", label: "peer rejects", run: func(ctx context.Context, e *env, _ Owner, g *guestID, _ string) error {
			return e.m.ContactRejected(ctx, e.account, g.Fingerprint)
		}},
		{from: "pending_out", label: "owner withdraws", run: remove},
		{from: "pending_out", label: "expires", run: expire},
		{from: "active", label: "owner blocks", run: block},
		{from: "active", label: "remove_contact", run: remove},
		{from: "active", label: "remove_contact", run: func(ctx context.Context, e *env, _ Owner, g *guestID, _ string) error {
			return e.m.RemoveContact(ctx, e.account, g.Fingerprint) // the peer's remove_contact, inbound
		}},
		{from: "blocked", label: "once active", everActive: true, run: unblock},
		{from: "blocked", label: "never was", run: unblock},
		{from: "blocked", label: "owner removes", run: remove},
	}

	reached := map[int]bool{}
	for _, c := range cases {
		e := newEnv(t)
		ctx := context.Background()
		g, card, spki := guest(t, "Peer")
		seed := c.from
		if c.from == "blocked" && c.everActive {
			seed = "active"
		} else if c.from == "blocked" {
			seed = "pending_in"
		}
		if _, err := e.st.InsertContact(ctx, store.Contact{
			AccountID: e.account, Fingerprint: g.Fingerprint, SPKI: spki, Leaf: g.Host.LeafDER,
			Status: seed, Card: card, CreatedAt: e.clock.Unix(),
		}); err != nil {
			t.Fatal(err)
		}
		if seed != c.from {
			if err := e.st.UpdateContactStatus(ctx, e.account, g.Fingerprint, c.from); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.run(ctx, e, Owner{Manager: e.m}, g, card); err != nil {
			t.Fatalf("%s from %s: %v", c.label, c.from, err)
		}
		got := "none"
		if row, err := e.st.GetContact(ctx, e.account, g.Fingerprint); err == nil {
			got = row.Status
		}
		found := false
		for i, ed := range edges {
			if ed.from == c.from && ed.to == got && strings.Contains(ed.label, c.label) {
				reached[i], found = true, true
			}
		}
		if !found {
			t.Errorf("the code takes %s to %s on %q; SPEC §9.1 draws no such edge", c.from, got, c.label)
		}
	}
	for i, ed := range edges {
		if ed.from != "[*]" && ed.from != "none" && !reached[i] {
			t.Errorf("SPEC §9.1 draws %s --> %s : %q and no case here runs it", ed.from, ed.to, ed.label)
		}
	}
}

type lifecycleEdge struct{ from, to, label string }

// specLifecycleEdges reads the stateDiagram of SPEC §9.1.
func specLifecycleEdges(t *testing.T) []lifecycleEdge {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "### 9.1 Contact lifecycle")
	if i < 0 {
		t.Fatal("SPEC.md has no §9.1 where this test reads it")
	}
	s = s[i:]
	a := strings.Index(s, "```mermaid")
	if a < 0 {
		t.Fatal("SPEC §9.1 has no mermaid diagram")
	}
	s = s[a+len("```mermaid"):]
	s = s[:strings.Index(s, "```")]
	re := regexp.MustCompile(`^\s*(\S+)\s*-->\s*(\S+)\s*(?::\s*(.*))?$`)
	var out []lifecycleEdge
	for _, line := range strings.Split(s, "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			label := strings.NewReplacer("<br/>", " ", "  ", " ").Replace(m[3])
			out = append(out, lifecycleEdge{m[1], m[2], label})
		}
	}
	if len(out) < 10 {
		t.Fatalf("read only %d edges from SPEC §9.1: the reader is broken, not the diagram", len(out))
	}
	return out
}

// contactStatusesAdmitted is the status list of the newest SQLite migration that constrains the
// contacts table's status column.
func contactStatusesAdmitted(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "sqlite", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations: %v", err)
	}
	sort.Strings(files)
	re := regexp.MustCompile(`(?is)CREATE TABLE\s+(?:IF NOT EXISTS\s+)?contacts\b.*?status\s+TEXT NOT NULL CHECK \(status IN \(([^)]*)\)\)`)
	var list []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := re.FindSubmatch(b); m != nil {
			list = nil
			for _, v := range strings.Split(string(m[1]), ",") {
				list = append(list, strings.Trim(strings.TrimSpace(v), "'"))
			}
		}
	}
	if len(list) == 0 {
		t.Fatal("no migration constrains contacts.status where this test reads it")
	}
	return list
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

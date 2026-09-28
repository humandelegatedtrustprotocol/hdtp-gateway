package public

import (
	"strings"
	"testing"
)

// Every sealed_call row names who acted: a stranger whose envelope was refused is a guest, a
// contact whose call ran is a contact. Every row used to be written as the node's own (`system`),
// so the audit trail could not tell a stranger's knock from the node's housekeeping; the cloud's
// conformance battery, aimed at a node (harness S19), asks the trail for a guest and found none.
func TestSealedCallsAreAuditedAsWhoActed(t *testing.T) {
	s := newSealedEnv(t)
	var rows []string
	s.deps.AuditAs = func(kind, action, resource, outcome string) {
		rows = append(rows, kind+" "+action+" "+outcome)
	}
	stranger := newPeer(t, s.nowAt)
	friend := newPeer(t, s.nowAt)
	s.pin(t, friend, "active")

	// A stranger's sealed send_message carries no card: refused before anything is dispatched.
	s.call(t, s.sealFrom(t, stranger, "chain", "send_message", nil), TransportFacts{})
	// The control: a contact's call that runs.
	s.call(t, s.sealFrom(t, friend, "chain", "get_card", nil), TransportFacts{})

	if len(rows) != 2 {
		t.Fatalf("rows: %q", rows)
	}
	if !strings.HasPrefix(rows[0], "guest sealed_call ") || strings.HasSuffix(rows[0], " ok") {
		t.Errorf("the stranger's refused envelope was audited as %q, want a guest's refusal", rows[0])
	}
	if rows[1] != "contact sealed_call ok" {
		t.Errorf("the contact's call was audited as %q, want contact sealed_call ok", rows[1])
	}
}

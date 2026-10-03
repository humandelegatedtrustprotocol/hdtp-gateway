package node

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
)

// The review of 2026-09-28 on the campaign after an import (HDTP §9.2) and after a move (§5.3).

// importInto writes one contact as an import does, owed this host's handshake from `at`.
func importInto(t *testing.T, d *demoNode, c store.Contact, at time.Time) {
	t.Helper()
	c.AccountID = d.acct.ID
	c.TrustFlag = "messages_only"
	c.HandshakeDueAt = at.Unix()
	if err := d.st.ImportContact(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func importPeer(t *testing.T, d, peer *demoNode, added, at time.Time) {
	t.Helper()
	importInto(t, d, store.Contact{
		Fingerprint: peer.rootFpr(), SPKI: peer.leafSPKI(), Status: "active", DisplayName: peer.acct.DisplayName,
		Endpoint: peer.endpoint(), Leaf: peer.leaf(), RootCert: peer.rc, EverActive: true, CreatedAt: added.Unix(),
	}, at)
}

// H1. A contact the handshake falls back to request_contact for waits as pending_out, and the
// request-expiry sweep reads how long a request has waited. The row kept the date the contact was
// ADDED, so a contact known for more than the window was swept within the hour, taking its pin
// with it, and the peer's later contact_accepted was refused.
func TestAFallbackRequestIsNotSweptForTheContactsAge(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	chitra := startDemoNode(t, clock, dn, "chitra", "Chitra Iyer", 365)
	importPeer(t, alina, chitra, clock.now().Add(-400*24*time.Hour), clock.now())

	clock.advance(time.Hour)
	res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	if _, _, err := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid); err != nil {
		t.Fatal(err)
	}
	if c := alina.contact(chitra.rootFpr()); c.Status != "pending_out" {
		t.Fatalf("the fallback must leave chitra pending_out: %q\n%s", c.Status, strings.Join(alina.log, "\n"))
	}
	owner := contacts.Owner{Manager: &contacts.Manager{Store: alina.st, Now: clock.now}}
	if gone, err := owner.ExpireRequests(ctx, alina.acct.ID, contacts.DefaultRequestExpiry); err != nil || len(gone) != 0 {
		t.Fatalf("the sweep removed a request made an hour ago: %+v %v", gone, err)
	}
	if c := alina.contact(chitra.rootFpr()); c.Status != "pending_out" || len(c.Leaf) == 0 {
		t.Fatalf("after the sweep chitra must still be pending_out with her pin: %+v", c)
	}
	// It still expires: the window runs from the request.
	clock.advance(contacts.DefaultRequestExpiry + time.Hour)
	if gone, err := owner.ExpireRequests(ctx, alina.acct.ID, contacts.DefaultRequestExpiry); err != nil || len(gone) != 1 {
		t.Fatalf("a request unanswered for the whole window must expire: %+v %v", gone, err)
	}
}

// M1. The fallback is for contacts an import brought, which may never have accepted this
// identity. An ordinary contact that refuses update_contact during a move is not asked to become
// a contact: it is left `pending`, retried by the next run, and its row is left as it was.
func TestAMoveDoesNotAskARefusingContactThatWasNotImported(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	xavier := startDemoNode(t, clock, dn, "xavier", "Xavier Roy", 365)
	alina.pinPeer(xavier) // xavier does not hold alina, so he refuses update_contact

	alina.n.SetPublicURL("https://alina-new.test")
	dn.set("alina-new.test", dn.hosts["alina.test"])
	mv := alina.install(identity.PurposeMove, identity.EndpointFor("https://alina-new.test", alina.slug), 365, clock.now())
	done, failed, err := alina.n.AnnounceMove(ctx, alina.acct.ID, mv.Kid)
	if err != nil || done != 0 || failed != 1 {
		t.Fatalf("a refusing contact is not told: done=%d failed=%d err=%v\n%s", done, failed, err, strings.Join(alina.log, "\n"))
	}
	if _, err := xavier.st.GetContact(ctx, xavier.acct.ID, alina.rootFpr()); err == nil {
		t.Fatal("xavier was sent request_contact for a contact the import did not bring")
	}
	if c := alina.contact(xavier.rootFpr()); c.Status != "active" {
		t.Fatalf("alina's row changed: %q", c.Status)
	}
}

// Coordinator item 1 (standing rule 5): a renewal at the same address is not a move. Its campaign
// is the handshake the imported contacts are owed and nothing more: the fifty ordinary contacts
// are not called.
func TestARenewalAfterAnImportCallsOnlyTheImportedContacts(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	for i := 0; i < 50; i++ {
		if _, err := alina.st.InsertContact(ctx, store.Contact{
			AccountID: alina.acct.ID, Fingerprint: fmt.Sprintf("sha256:ordinary-%02d", i), SPKI: bharat.leafSPKI(), Status: "active",
			Permissions: []string{"message.text"}, Endpoint: fmt.Sprintf("https://ordinary-%02d.test/a/x/mcp", i), Leaf: bharat.leaf(), PinnedAt: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		importInto(t, alina, store.Contact{
			Fingerprint: fmt.Sprintf("sha256:imported-%d", i), SPKI: bharat.leafSPKI(), Status: "active",
			Endpoint: fmt.Sprintf("https://imported-%d.test/a/x/mcp", i), Leaf: bharat.leaf(), EverActive: true,
		}, clock.now())
	}
	clock.advance(time.Hour)
	res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	if res.Moved || res.HandshakesDue != 3 {
		t.Fatalf("a renewal owing three handshakes: %+v", res)
	}
	done, failed, _ := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid)
	if done+failed != 3 {
		t.Fatalf("the renewal's campaign called %d contacts, want the 3 imported ones\n%s", done+failed, strings.Join(alina.log, "\n"))
	}
	prog, err := alina.n.MoveProgress(ctx, alina.acct.ID, res.Kid)
	if err != nil || prog.Waiting != 3 {
		t.Fatalf("waiting are the three unreachable imported contacts, not the ordinary ones: %+v %v", prog, err)
	}
	// Detached, as the install starts it: a handshake is not audited as a move campaign.
	if !alina.n.ResumeMove(ctx, alina.acct.ID, res.Kid) {
		t.Fatal("no walk started")
	}
	waitWalk(t, alina)
	trail := strings.Join(alina.log, "\n")
	if strings.Contains(trail, "account_move_campaign") || !strings.Contains(trail, "account_handshake_campaign account:"+alina.acct.ID) {
		t.Fatalf("a renewal's walk is the handshake campaign, not a move campaign:\n%s", trail)
	}
}

// refuseInserts makes a node's store refuse every new contact row: raw SQL, in a test only.
func refuseInserts(t *testing.T, d *demoNode) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(d.dir, d.slug+".db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER refuse_contacts BEFORE INSERT ON contacts BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
}

func waitWalk(t *testing.T, d *demoNode) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if _, walking := d.n.campaigns.Load(d.acct.ID); !walking {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("the walk did not end")
}

// Coordinator item 2. An imported contact that refuses update_contact AND request_contact has
// answered: its mark is cleared, the outcome is the literal `refused`, and a re-run never asks it
// again. It used to be recorded `pending` and asked on every run for ever.
func TestARefusedHandshakeIsNotAskedAgain(t *testing.T) {
	for _, move := range []bool{false, true} {
		t.Run(map[bool]string{false: "renewal", true: "move"}[move], func(t *testing.T) { refusedHandshake(t, move) })
	}
}

func refusedHandshake(t *testing.T, move bool) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	dmitri := startDemoNode(t, clock, dn, "dmitri", "Dmitri Volkov", 365)
	// Dmitri does not hold alina, so update_contact is refused; and his node refuses to record a
	// request (the insert fails, which request_contact answers `bad_request`): a refusal that is an
	// answer, not a failure to arrive.
	refuseInserts(t, dmitri)
	importPeer(t, alina, dmitri, clock.now().Add(-24*time.Hour), clock.now())
	clock.advance(time.Hour)
	var res identity.InstallResult
	if move {
		// A move walks every active contact too: the refusal must still end the asking.
		alina.n.SetPublicURL("https://alina-new.test")
		dn.set("alina-new.test", dn.hosts["alina.test"])
		res = alina.install(identity.PurposeMove, identity.EndpointFor("https://alina-new.test", alina.slug), 365, clock.now())
		alina.host = "alina-new.test"
	} else {
		res = alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	}
	calls := func() int { return strings.Count(strings.Join(dmitri.log, "\n"), "sealed_call ") }
	if _, _, err := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid); err != nil {
		t.Fatal(err)
	}
	asked := calls()
	if !strings.Contains(strings.Join(dmitri.log, "\n"), "request_contact ") {
		t.Fatalf("dmitri must be asked once:\n%s", strings.Join(dmitri.log, "\n"))
	}
	c := alina.contact(dmitri.rootFpr())
	if c.HandshakeDue || c.Status != "active" {
		t.Fatalf("a refused handshake clears the mark and leaves the row as the import wrote it: status=%s due=%v", c.Status, c.HandshakeDue)
	}
	if !strings.Contains(strings.Join(alina.log, "\n"), "account_move_fanout account:"+alina.acct.ID+" contact:"+dmitri.rootFpr()+" → refused") {
		t.Fatalf("the refusal is audited as `refused`:\n%s", strings.Join(alina.log, "\n"))
	}
	if _, _, err := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid); err != nil {
		t.Fatal(err)
	}
	if calls() != asked {
		t.Fatalf("a re-run called dmitri again: %d calls, then %d", asked, calls())
	}
	if prog, _ := alina.n.MoveProgress(ctx, alina.acct.ID, res.Kid); prog.Waiting != 0 || prog.Refused != 1 {
		t.Fatalf("a refused contact is counted apart and not waiting: %+v", prog)
	}
}

// L6. The row is pending_out BEFORE request_contact leaves, so a peer that answers at once finds
// the approach it is answering. And a request that never arrived is taken back.
func TestTheFallbackRecordsTheApproachBeforeSendingIt(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	chitra := startDemoNode(t, clock, dn, "chitra", "Chitra Iyer", 365)
	importPeer(t, alina, chitra, clock.now().Add(-24*time.Hour), clock.now())
	var seen []string
	chitra.onAudit(func(line string) {
		if strings.HasPrefix(line, "request_contact ") {
			c, _ := alina.st.GetContact(ctx, alina.acct.ID, chitra.rootFpr())
			seen = append(seen, c.Status)
		}
	})
	clock.advance(time.Hour)
	res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	if _, _, err := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "pending_out" {
		t.Fatalf("when chitra had the request, alina held her as %v, want [pending_out]", seen)
	}
}

// L6's other half: request_contact that never reached the peer takes the approach back, leaving
// the row as the import wrote it and the contact owed the handshake. (Green on d039bbe, which
// marked the row only after the request had landed: this guards the new order's compensation.)
func TestAFallbackThatDidNotArriveIsTakenBack(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	chitra := startDemoNode(t, clock, dn, "chitra", "Chitra Iyer", 365)
	importInto(t, alina, store.Contact{
		Fingerprint: chitra.rootFpr(), SPKI: chitra.leafSPKI(), Status: "active", DisplayName: chitra.acct.DisplayName,
		Endpoint: chitra.endpoint(), Leaf: chitra.leaf(), RootCert: chitra.rc, EverActive: true,
	}, clock.now())
	// Chitra refuses update_contact, and is gone before request_contact reaches her.
	chitra.onAudit(func(line string) {
		if strings.HasPrefix(line, "sealed_call ") && strings.HasSuffix(line, "envelope_invalid") {
			dn.mu.Lock()
			delete(dn.hosts, chitra.host)
			dn.mu.Unlock()
		}
	})
	clock.advance(time.Hour)
	res := alina.install(identity.PurposeRenew, alina.endpoint(), 365, clock.now())
	_, failed, _ := alina.n.AnnounceMove(ctx, alina.acct.ID, res.Kid)
	if failed != 1 {
		t.Fatalf("the contact was not reached: failed=%d\n%s\n--\n%s", failed, strings.Join(alina.log, "\n"), strings.Join(chitra.log, "\n"))
	}
	c := alina.contact(chitra.rootFpr())
	if c.Status != "active" || !c.HandshakeDue || !c.EverActive {
		t.Fatalf("a request that did not arrive must be taken back, the mark kept: status=%s ever_active=%v due=%v", c.Status, c.EverActive, c.HandshakeDue)
	}
}

// L5. `account announce` before the leaf that follows an import must not spend the handshakes on
// the leaf the import found: they are owed from the NEXT leaf.
func TestTheHandshakeIsNotSpentOnTheLeafTheImportFound(t *testing.T) {
	ctx := context.Background()
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	bharat := startDemoNode(t, clock, dn, "bharat", "Bharat Mehta", 365)
	bharat.pinPeer(alina)
	clock.advance(time.Hour)
	importPeer(t, alina, bharat, clock.now().Add(-24*time.Hour), clock.now())
	prog, err := alina.n.MoveProgress(ctx, alina.acct.ID, alina.acct.Fingerprint)
	if err != nil || prog.Waiting != 0 {
		t.Fatalf("nothing waits on the leaf the import found: %+v %v", prog, err)
	}
	done, failed, err := alina.n.AnnounceMove(ctx, alina.acct.ID, alina.acct.Fingerprint)
	if err != nil || done+failed != 0 {
		t.Fatalf("a walk for the old leaf called %d contact(s): %v", done+failed, err)
	}
	if !alina.contact(bharat.rootFpr()).HandshakeDue {
		t.Fatal("the handshake was spent on the old leaf")
	}
}

// L2 (review 2026-09-28). A leave holds the account's campaign slot from its check to the end of
// its erase: no walk can start in between (ResumeMove from `account announce`, or an install).
func TestNoCampaignStartsWhileTheWorkHoldsTheSlot(t *testing.T) {
	clock := &demoClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	dn := &demoNet{hosts: map[string]string{}}
	alina := startDemoNode(t, clock, dn, "alina", "Alina Rao", 365)
	ran := false
	err := alina.n.WithoutCampaign(alina.acct.ID, func() error {
		ran = true
		if alina.n.ResumeMove(context.Background(), alina.acct.ID, alina.acct.Fingerprint) {
			t.Fatal("a campaign started while the slot was held")
		}
		if err := alina.n.WithoutCampaign(alina.acct.ID, func() error { return nil }); err != ErrCampaignWalking {
			t.Fatalf("a second holder: %v", err)
		}
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("the work: %v %v", ran, err)
	}
	if _, held := alina.n.campaigns.Load(alina.acct.ID); held {
		t.Fatal("the slot was not released")
	}
}

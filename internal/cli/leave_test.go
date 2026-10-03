package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/identity"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/integrations"
)

// What the public listener answers at an identity's address and at its invite link, as the status
// and the body with the slug and the token taken out, so two addresses can be compared.
func publicAnswer(t *testing.T, public, slug, token string) string {
	t.Helper()
	var out []string
	for _, path := range []string{"/a/" + slug + "/mcp", "/i/" + token} {
		res := insecureGet(t, "https://"+public+path)
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		body := strings.ReplaceAll(strings.ReplaceAll(string(b), slug, "SLUG"), token, "TOKEN")
		out = append(out, res.Status+" "+body)
	}
	return strings.Join(out, "\n")
}

// `account leave` on a running node (HDTP §9, "What a host must do when the person leaves"): the
// refusals, then one leave that must go through, after which the address answers exactly as an
// address this node never served — the control is a slug that was never created, and before the
// leave the same comparison must DIFFER, or it would prove nothing.
func TestAccountLeaveOnARunningNode(t *testing.T) {
	ctx := context.Background()
	var alice store.Account
	var slowRoot, oauthIntegration string
	// A contact whose host accepts a connection and says nothing for a while: the move campaign's
	// walk waits on it, which is the one state leave refuses.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	r := runServe(t, func(t *testing.T, dir string) {
		st, err := store.OpenSQLite(filepath.Join(dir, "hdtp.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		idm := &identity.Manager{Store: st, Keyring: openKeyringAt(t, dir)}
		for _, slug := range []string{"alice", "bob"} {
			a, err := idm.CreateAccount(ctx, slug, strings.ToUpper(slug[:1])+slug[1:], identity.AlgoP256)
			if err != nil {
				t.Fatal(err)
			}
			a = issueLeafFor(t, idm, a, configPublicURL(t, dir))
			if slug == "alice" {
				alice = a
			}
		}
		// M2 (review 2026-09-28): an integration of alice's with a pre-registered OAuth client, whose
		// credentials are a settings row keyed by the integration's id.
		in, err := st.InsertIntegration(ctx, store.Integration{AccountID: alice.ID, Slug: "cal", Transport: "streamable-http", Endpoint: "https://cal.example/mcp", AuthKind: "oauth", Status: "disabled"})
		if err != nil {
			t.Fatal(err)
		}
		oauthIntegration = in.ID
		if err := integrations.SealClient(st, idm.Keyring, core.SettingsAAD(), in.ID, "client-id", "client-secret"); err != nil {
			t.Fatal(err)
		}
		peer := newTestPeer(t, "Slow", "https://"+hold.Addr().String()+"/a/slow/mcp")
		slowRoot = peer.Root()
		// An imported contact, owed the handshake: the campaign `announce` resumes walks it.
		if err := st.ImportContact(ctx, store.Contact{AccountID: alice.ID, Fingerprint: peer.Root(), Status: "active", TrustFlag: "messages_only",
			Endpoint: peer.Endpoint, Leaf: peer.Host.LeafDER, SPKI: []byte{1}, RootCert: peer.Wallet.RootDER, HandshakeDueAt: 1}); err != nil {
			t.Fatal(err)
		}
	})
	cfg := filepath.Join(r.dir, "config.json")
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := account(append(args, "-config", cfg), &out, &errb)
		return code, out.String() + errb.String()
	}
	st := openStoreAt(t, r.dir)
	token, _, err := (&contacts.Manager{Store: st}).CreateInvite(ctx, alice.ID, contacts.InviteOptions{MaxUses: 1, Preset: "friend"})
	if err != nil {
		t.Fatal(err)
	}
	const never = "zed"
	neverToken := strings.Repeat("0", len(token))
	if publicAnswer(t, r.public, "alice", token) == publicAnswer(t, r.public, never, neverToken) {
		t.Fatal("before leaving, alice's address already answers as one never served: the comparison below would prove nothing")
	}

	// Refused: no slug (the argument is malformed), and a slug this node does not hold.
	if code, out := run("leave"); code == 0 || !strings.Contains(out, "needs slug") {
		t.Fatalf("leave with no slug: %d %s", code, out)
	}
	if code, out := run("leave", "-slug", never); code == 0 || !strings.Contains(out, "unknown slug") {
		t.Fatalf("leave of a slug never created: %d %s", code, out)
	}
	// Refused: a move campaign is walking (alice's one contact has not been told, and its host is
	// holding the walk).
	if code, out := run("announce", "-slug", "alice"); code != 0 || !strings.Contains(out, "resumed") {
		t.Fatalf("announce did not start the walk: %d %s", code, out)
	}
	if code, out := run("leave", "-slug", "alice", "-yes"); code == 0 || !strings.Contains(out, "telling its contacts of a move right now") {
		t.Fatalf("leave during a walk: %d %s", code, out)
	}
	if _, err := st.GetAccountByID(ctx, alice.ID); err != nil {
		t.Fatalf("a refused leave erased the account: %v", err)
	}
	// Once the walk has given up on the silent host, the leave goes through. The contact is blocked
	// first, so it is no longer owed the move and no announce starts another walk.
	if err := st.UpdateContactStatus(ctx, alice.ID, slowRoot, "blocked"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, out := run("announce", "-slug", "alice")
		if !strings.Contains(out, "walk is under way") && !strings.Contains(out, "resumed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the walk never finished: %s", out)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// QA 1 (2026-09-28): without -yes, the review of what would go, and nothing erased.
	code, out := run("leave", "-slug", "alice")
	if code != 0 || !strings.Contains(out, "leaving would erase alice") || !strings.Contains(out, "1 contact(s)") || !strings.Contains(out, "nothing was erased") {
		t.Fatalf("leave without -yes: %d %s", code, out)
	}
	if _, err := st.GetAccountByID(ctx, alice.ID); err != nil {
		t.Fatalf("the review erased the account: %v", err)
	}
	// The erase does not reach the audit trail (SPEC §3.11): what it holds of the identity before
	// the leave, it holds after it, row for row — the account id, the slug and the contacts'
	// fingerprints — and the leave adds its own account_leave row and nothing else. They stay in
	// the live trail for audit_archive_after (90 days by default, this node's setting), and the
	// end of this test restarts the node with a period of nothing to see them moved.
	namesAlice := func(e store.AuditRow) bool {
		return e.AccountID == alice.ID || strings.Contains(e.Resource, alice.ID)
	}
	before := map[int64]store.AuditRow{}
	rowsBefore, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rowsBefore {
		if namesAlice(e) {
			before[e.Seq] = e
		}
	}
	code, out = run("leave", "-slug", "alice", "-yes")
	if code != 0 || !strings.Contains(out, "alice has left this node") || !strings.Contains(out, "/a/alice/mcp stays reserved until") {
		t.Fatalf("leave: %d %s", code, out)
	}
	rowsAfter, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var added []store.AuditRow
	kept := 0
	sawSlug, sawContact := false, false
	for _, e := range rowsAfter {
		if !namesAlice(e) {
			continue
		}
		if b, ok := before[e.Seq]; ok {
			if b != e {
				t.Fatalf("the leave changed an audit row: %+v -> %+v", b, e)
			}
			kept++
		} else {
			added = append(added, e)
		}
		sawSlug = sawSlug || strings.Contains(e.Resource, "slug:alice")
		sawContact = sawContact || strings.Contains(e.Resource, slowRoot)
	}
	if kept != len(before) || len(added) != 1 || added[0].Action != "account_leave" || added[0].Outcome != "ok" {
		t.Fatalf("after the leave the trail keeps %d of %d rows naming the identity and adds %+v; want all of them and one account_leave ok", kept, len(before), added)
	}
	if !sawSlug || !sawContact {
		t.Fatalf("the rows kept name the slug (%v) and a contact's fingerprint (%v): the prose says they do", sawSlug, sawContact)
	}
	if got, want := publicAnswer(t, r.public, "alice", token), publicAnswer(t, r.public, never, neverToken); got != want {
		t.Fatalf("the vacated address answers unlike one never served:\n%s\n---\n%s", got, want)
	}
	// The OAuth client's credentials went with the identity (M2).
	settingsLeft, err := st.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range settingsLeft {
		if strings.Contains(row.Key, oauthIntegration) {
			t.Fatalf("the leave left a settings row of alice's integration: %s", row.Key)
		}
	}
	// Bob, on the same node, is untouched.
	if _, err := st.GetAccountBySlug(ctx, "bob"); err != nil {
		t.Fatalf("bob went with alice: %v", err)
	}
	// The slug is reserved: a new identity cannot be created under it.
	if code, out := run("create", "-slug", "alice", "-name", "Someone Else"); code == 0 || !strings.Contains(out, "vacated") {
		t.Fatalf("a new identity took alice's address: %d %s", code, out)
	}
	// And the audit trail names the account, with each outcome as it happened.
	events, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, e := range events {
		if e.Action == "account_leave" {
			if e.AccountID != alice.ID {
				t.Errorf("account_leave row names account %q, want %q", e.AccountID, alice.ID)
			}
			seen = append(seen, e.Outcome)
		}
	}
	if strings.Join(seen, ",") != "refused,ok" {
		t.Fatalf("account_leave rows %v, want one refused then one ok", seen)
	}

	// QA 1 (2026-09-28): bob's current leaf names this node's own address for him — he is served
	// here, now (after a move to another address on this node, "delete it at the old host" names
	// this node). The leave is refused unless the person says they mean the live identity.
	bob, err := st.GetAccountBySlug(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range mustLeaves(t, st, bob.ID) {
		if l.State == identity.LeafCurrent {
			l.Endpoint = identity.EndpointFor("https://"+r.public, "bob")
			if err := st.UpdateLeaf(ctx, l); err != nil {
				t.Fatal(err)
			}
		}
	}
	if code, out := run("leave", "-slug", "bob", "-yes"); code == 0 || !strings.Contains(out, "is served here, now") || !strings.Contains(out, "-force-current") {
		t.Fatalf("leave of an identity served here at this node's address: %d %s", code, out)
	}
	if _, err := st.GetAccountByID(ctx, bob.ID); err != nil {
		t.Fatalf("a refused leave erased bob: %v", err)
	}
	if code, out := run("leave", "-slug", "bob", "-yes", "-force-current"); code != 0 || !strings.Contains(out, "bob has left this node") {
		t.Fatalf("leave with -force-current: %d %s", code, out)
	}
	// Within the period nothing has moved: the trail still names both, and there is no archive.
	live, err := st.ListAuditEvents(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{alice.ID, bob.ID} {
		if n := countNaming(live, id); n == 0 {
			t.Fatalf("within the period the live trail lost the rows of %s", id)
		}
	}
	archiveDir := filepath.Join(r.dir, "audit-archive")
	if files, _ := filepath.Glob(filepath.Join(archiveDir, "*.jsonl")); len(files) != 0 {
		t.Fatalf("within the period the node archived %v", files)
	}

	// L14 (the owner's decision, 2026-09-28: "audit trail goes to archive eventually"). The node
	// restarts with a period of nothing; its sweep runs at start, and moves every row that names
	// either identity by its account id to a file of that identity's own.
	if code := r.stop(); code != 0 {
		t.Fatalf("serve exited %d: %s", code, r.out.String())
	}
	setConfig(t, cfg, "audit_archive_after", "0s")
	r = startServeAt(t, r.dir, cfg, r.internal, r.public)
	deadline = time.Now().Add(30 * time.Second)
	for {
		if live, err = st.ListAuditEvents(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if countNaming(live, alice.ID)+countNaming(live, bob.ID) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sweep never archived the trail: %s", r.out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	// What the live trail holds of them now: nothing by their ids, and nothing by the slugs or the
	// contact's fingerprint either — every row this test's node wrote that names a slug or a
	// fingerprint of theirs names the account id too.
	for _, e := range live {
		for _, what := range []string{"slug:alice", "slug:bob", slowRoot} {
			if strings.Contains(e.Resource, what) || strings.Contains(e.Details, what) {
				t.Errorf("after the archive a live row still names %s: %+v", what, e)
			}
		}
	}
	var marks []store.AuditRow
	for _, e := range live {
		if e.Action == "audit_archive" {
			marks = append(marks, e)
		}
	}
	if len(marks) != 2 || marks[0].AccountID != "" || marks[1].AccountID != "" {
		t.Fatalf("audit_archive rows %+v, want one per identity, naming neither", marks)
	}
	files, _ := filepath.Glob(filepath.Join(archiveDir, "*.jsonl"))
	if len(files) != 2 {
		t.Fatalf("archives %v, want alice's and bob's", files)
	}
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s is mode %v, want 0600", f, fi.Mode().Perm())
		}
	}
	// The chain verifies across the table and the archives, offline, as the owner would check it.
	if code := r.stop(); code != 0 {
		t.Fatalf("serve exited %d: %s", code, r.out.String())
	}
	verify := func() (int, string) {
		var out, errb bytes.Buffer
		code := auditCmd([]string{"verify", "-config", cfg}, &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := verify(); code != 0 || !strings.Contains(out, "2 identity archive file(s)") || !strings.Contains(out, "intact") {
		t.Fatalf("audit verify after the archive: %d %s", code, out)
	}
	aliceFile := ""
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), alice.ID+"-") {
			aliceFile = f
		}
	}
	raw, err := os.ReadFile(aliceFile)
	if err != nil {
		t.Fatalf("no archive of alice's: %v (%v)", err, files)
	}
	if err := os.WriteFile(aliceFile, []byte(strings.Replace(string(raw), "slug:alice", "slug:alicf", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := verify(); code == 0 || !strings.Contains(out, "BROKEN") {
		t.Fatalf("a tampered archive verified: %d %s", code, out)
	}
	if err := os.WriteFile(aliceFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Law requires alice's archive to go: its rows' content goes, the chain still verifies, and
	// the erase is audited.
	var eraseOut bytes.Buffer
	if code := auditCmd([]string{"erase-archive", "-config", cfg, "-file", filepath.Base(aliceFile)}, &eraseOut, &eraseOut); code != 0 {
		t.Fatalf("erase-archive: %d %s", code, eraseOut.String())
	}
	if code, out := verify(); code != 0 || !strings.Contains(out, "erased") || !strings.Contains(out, "intact") {
		t.Fatalf("audit verify after an erase: %d %s", code, out)
	}
	if live, err = st.ListAuditEvents(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if last := live[len(live)-1]; last.Action != "audit_archive_erase" || last.ActorKind != "cli" || strings.Contains(last.Resource, alice.ID) {
		t.Fatalf("the erase's audit row is %+v", last)
	}
}

// countNaming counts the rows that name an account by its id, where the archive looks for it
// (audit.Names): the account column and the resource.
func countNaming(rows []store.AuditRow, id string) int {
	n := 0
	for _, e := range rows {
		if e.AccountID == id || strings.Contains(e.Resource, id) {
			n++
		}
	}
	return n
}

// setConfig sets one key of a JSON config file.
func setConfig(t *testing.T, path, key string, value any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m[key] = value
	if b, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

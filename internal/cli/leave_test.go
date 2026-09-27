package cli

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/internal/contacts"
	"github.com/pact-cloud/pact-gateway/internal/core"
	"github.com/pact-cloud/pact-gateway/internal/core/store"
	"github.com/pact-cloud/pact-gateway/internal/identity"
	"github.com/pact-cloud/pact-gateway/internal/integrations"
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

// `account leave` on a running node (PACT §9, "What a host must do when the person leaves"): the
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
		st, err := store.OpenSQLite(filepath.Join(dir, "pact.db"))
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
	if code, out := run("leave", "-slug", "alice"); code == 0 || !strings.Contains(out, "telling its contacts of a move right now") {
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
	code, out := run("leave", "-slug", "alice")
	if code != 0 || !strings.Contains(out, "alice has left this node") || !strings.Contains(out, "/a/alice/mcp stays reserved until") {
		t.Fatalf("leave: %d %s", code, out)
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
}

package scenario

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pact-cloud/pact-gateway/harness/owner"
	"github.com/pact-cloud/pact-gateway/harness/registry"
	"github.com/pact-cloud/pact-gateway/harness/topology"
)

// S21 — the journeys the node had no scenario for, between two real nodes, through their owners'
// own door (the owner MCP) and the CLI where the CLI is the door (leave):
//
//   - an owner redeeming their own invite is refused, and nothing is pinned;
//   - a revoked invite is refused, and the peer is left with nothing;
//   - an auto-accept invite makes both sides active (the control the refusals are measured by);
//   - every owner tool that names a contact, given a contact nobody holds, refuses and creates nothing;
//   - a block refuses the blocked peer's message, and an unblock restores the contact as it was;
//   - a removal reaches the peer, and the removed peer's message is refused;
//   - a token scoped to one identity reaches that identity and not another on the same node;
//   - an identity that leaves is gone: its peer's message is refused, and its address stays
//     reserved (no new account may take the slug while a leaf naming it is alive).
//
// The cloud's pair proves the same journeys through its own doors (e2e/tables/scenarios.mjs S1, S6,
// S5b, S14, S18, S13, S5, T41a–c); the journey list both hold is docs/release/node-functional-suite-2026-09-28.md §2.2.
func TestTheJourneysTheNodeHadNoScenarioFor(t *testing.T) {
	ctx, w := begin(t, registry.Spec{
		ID: "S21", Name: "self-invite, revoked invite, phantoms, block and unblock, removal, a scoped token, and leave, between two nodes", Tier: registry.Nightly,
		Needs:   []registry.Need{registry.Docker, registry.NodeImage, registry.Chrome},
		Timeout: 25 * time.Minute,
	})
	net, err := w.LAN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seal := map[string]string{"PACT_SEAL": "optional"}
	alice, err := w.Node(ctx, NodeOpts{Slug: "alice", Net: net, Env: seal})
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := w.Node(ctx, NodeOpts{Slug: "bob", Net: net, Env: seal})
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	t.Run("an owner redeeming their own invite is refused", func(t *testing.T) {
		link := inviteLink(ctx, t, alice, true)
		code, _ := addContact(ctx, t, alice, link.URL)
		if code == "" {
			t.Errorf("alice added herself through her own invite")
		}
		if got := contactStatus(ctx, t, alice, alice.Fpr); got != "absent" {
			t.Errorf("alice holds herself as %q", got)
		}
	})

	t.Run("a revoked invite is refused", func(t *testing.T) {
		link := inviteLink(ctx, t, alice, true)
		if _, err := alice.Owner.Call(ctx, "revoke_invite", map[string]any{"account_id": alice.AccountID, "invite_id": link.InviteID}); err != nil {
			t.Fatalf("revoke_invite: %v", err)
		}
		if code, _ := addContact(ctx, t, bob, link.URL); code == "" {
			t.Errorf("bob redeemed a revoked invite")
		}
		if got := contactStatus(ctx, t, alice, bob.Fpr); got != "absent" {
			t.Errorf("after a revoked invite alice holds bob as %q", got)
		}
	})

	// The control every refusal above is measured by: the same door, a live invite, gets through.
	t.Run("an auto-accept invite makes both sides active", func(t *testing.T) {
		link := inviteLink(ctx, t, alice, true)
		if code, detail := addContact(ctx, t, bob, link.URL); code != "" {
			t.Fatalf("bob's redemption refused: %s %s", code, detail)
		}
		waitStatus(ctx, t, alice, bob.Fpr, "active")
		waitStatus(ctx, t, bob, alice.Fpr, "active")
		if err := send(ctx, bob, alice.Fpr, "hello from bob"); err != nil {
			t.Fatalf("an active contact's message: %v", err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for !inboxHas(ctx, t, alice, "hello from bob") {
			if time.Now().After(deadline) {
				t.Fatalf("an active contact's message never reached alice's inbox")
			}
			time.Sleep(2 * time.Second)
		}
	})

	t.Run("every tool that names a contact refuses one nobody holds", func(t *testing.T) {
		args, err := alice.Owner.ToolArgs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		const phantom = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		named := 0
		for tool, names := range args {
			if !slices.Contains(names, "contact_fpr") {
				continue
			}
			named++
			call := map[string]any{"account_id": alice.AccountID, "contact_fpr": phantom,
				"preset": "friend", "permissions": []string{"message.text"}, "petname": "x", "trust": "messages_only",
				"text": "to nobody", "msg_id": "phantom-" + tool, "tool": "get_card", "arguments": map[string]any{}}
			raw, err := alice.Owner.Call(ctx, tool, call)
			if err == nil && !refused(raw) {
				t.Errorf("%s on a contact nobody holds answered %s", tool, trim(raw))
			}
		}
		if named < 5 {
			t.Fatalf("%d tools take contact_fpr; the schema is not being read", named)
		}
		if got := contactStatus(ctx, t, alice, "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); got != "absent" {
			t.Errorf("a phantom is now held as %q", got)
		}
	})

	t.Run("a block refuses the peer, and an unblock restores it as it was", func(t *testing.T) {
		if _, err := alice.Owner.Call(ctx, "block_contact", map[string]any{"account_id": alice.AccountID, "contact_fpr": bob.Fpr}); err != nil {
			t.Fatalf("block_contact: %v", err)
		}
		if err := send(ctx, bob, alice.Fpr, "while blocked"); err == nil {
			t.Errorf("bob's message to a node that blocked him was answered as sent")
		}
		if inboxHas(ctx, t, alice, "while blocked") {
			t.Errorf("a blocked peer's message reached alice's inbox")
		}
		// unblock_contact: "a contact that was ever active returns as it was (status active)".
		if _, err := alice.Owner.Call(ctx, "unblock_contact", map[string]any{"account_id": alice.AccountID, "contact_fpr": bob.Fpr}); err != nil {
			t.Fatalf("unblock_contact: %v", err)
		}
		if got := contactStatus(ctx, t, alice, bob.Fpr); got != "active" {
			t.Fatalf("after unblock_contact alice holds bob as %q, want active as he was", got)
		}
		if err := send(ctx, bob, alice.Fpr, "after the unblock"); err != nil {
			t.Fatalf("after the unblock bob's message: %v", err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for !inboxHas(ctx, t, alice, "after the unblock") {
			if time.Now().After(deadline) {
				t.Fatalf("after the unblock bob's message never reached alice's inbox")
			}
			time.Sleep(2 * time.Second)
		}
	})

	t.Run("a removal reaches the peer, and its message is refused", func(t *testing.T) {
		if _, err := alice.Owner.Call(ctx, "remove_contact", map[string]any{"account_id": alice.AccountID, "contact_fpr": bob.Fpr}); err != nil {
			t.Fatalf("remove_contact: %v", err)
		}
		if got := contactStatus(ctx, t, alice, bob.Fpr); got == "active" {
			t.Errorf("alice still holds bob as active after removing him")
		}
		deadline := time.Now().Add(90 * time.Second)
		for contactStatus(ctx, t, bob, alice.Fpr) == "active" {
			if time.Now().After(deadline) {
				t.Fatalf("bob still holds alice as active: the removal never reached him")
			}
			time.Sleep(2 * time.Second)
		}
		if err := send(ctx, bob, alice.Fpr, "after the removal"); err == nil {
			t.Errorf("bob's message after his removal was answered as sent")
		}
	})

	t.Run("a token scoped to one identity reaches that one only", func(t *testing.T) {
		if _, _, err := topology.Certify(ctx, w.Fab, alice.Node, "alice2"); err != nil {
			t.Fatalf("a second identity on alice's node: %v", err)
		}
		accts, err := alice.Owner.Accounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		other := ""
		for _, id := range accts {
			if id != alice.AccountID {
				other = id
			}
		}
		if other == "" {
			t.Fatalf("the owner administers %v: the second identity is not among them", accts)
		}
		scoped := scopedToken(ctx, t, w, alice, alice.AccountID)
		oc, err := owner.Connect(ctx, "http://127.0.0.1:"+alice.OwnerPort+"/owner/mcp", scoped)
		if err != nil {
			t.Fatalf("the scoped token: %v", err)
		}
		defer oc.Close()
		mine, err := oc.Accounts(ctx)
		if err != nil || !slices.Equal(mine, []string{alice.AccountID}) {
			t.Errorf("the scoped token lists %v (%v), want only its own identity", mine, err)
		}
		if _, err := oc.Call(ctx, "list_contacts", map[string]any{"account_id": alice.AccountID}); err != nil {
			t.Errorf("the control: the scoped token on its own identity: %v", err)
		}
		for _, tool := range []string{"list_contacts", "get_inbox", "create_invite", "export_card"} {
			raw, err := oc.Call(ctx, tool, map[string]any{"account_id": other, "max_uses": 1})
			if err == nil && !refused(raw) {
				t.Errorf("%s on another identity through a scoped token answered %s", tool, trim(raw))
			}
		}
	})

	t.Run("an identity that leaves is gone, and its address stays reserved", func(t *testing.T) {
		link := inviteLink(ctx, t, alice, true)
		if code, detail := addContact(ctx, t, bob, link.URL); code != "" {
			t.Fatalf("bob's redemption before the leave refused: %s %s", code, detail)
		}
		waitStatus(ctx, t, bob, alice.Fpr, "active")
		// The review writes nothing; the identity still answers.
		if out, err := w.Fab.Exec(ctx, alice.Node, "/pact-gateway", "account", "leave", "-slug", "alice"); err != nil {
			t.Fatalf("account leave (the review): %v\n%s", err, out)
		}
		if err := send(ctx, bob, alice.Fpr, "after the review"); err != nil {
			t.Fatalf("a leave's review erased something: bob's message after it: %v", err)
		}
		// Alice is served at this node's own address for her, so erasing her takes -force-current.
		if out, err := w.Fab.Exec(ctx, alice.Node, "/pact-gateway", "account", "leave", "-slug", "alice", "-yes", "-force-current"); err != nil {
			t.Fatalf("account leave: %v\n%s", err, out)
		}
		if err := send(ctx, bob, alice.Fpr, "after alice left"); err == nil {
			t.Errorf("bob's message to an identity that left was answered as sent")
		}
		out, err := w.Fab.Exec(ctx, alice.Node, "/pact-gateway", "account", "create", "--slug", "alice", "--name", "Squatter")
		if err == nil || !strings.Contains(string(out), "reserved until the last leaf issued for it expires") {
			t.Errorf("a new account at the address alice left, while her leaf is alive, answered %v: %s — want the reservation's refusal", err, out)
		}
	})
}

// invite is what create_invite answers.
type inviteAnswer struct {
	Token    string `json:"token"`
	URL      string `json:"url"`
	InviteID string `json:"id"`
}

func inviteLink(ctx context.Context, t *testing.T, o *Owned, auto bool) inviteAnswer {
	t.Helper()
	var inv inviteAnswer
	if err := o.Owner.CallJSON(ctx, "create_invite", map[string]any{
		"account_id": o.AccountID, "label": "S21", "max_uses": 1, "auto_accept": auto, "preset": "friend",
	}, &inv); err != nil {
		t.Fatalf("create_invite: %v", err)
	}
	if inv.URL == "" || inv.InviteID == "" {
		t.Fatalf("create_invite answered no url or id: %+v", inv)
	}
	return inv
}

// addContact redeems a link through the owner's add_contact and returns the refusal, if any.
func addContact(ctx context.Context, t *testing.T, o *Owned, url string) (code, detail string) {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "add_contact", map[string]any{"account_id": o.AccountID, "invite_url": url, "grant": "friend"})
	if err != nil {
		return "refused", err.Error()
	}
	var a struct{ Code, Detail string }
	_ = json.Unmarshal([]byte(raw), &a)
	return a.Code, a.Detail
}

func waitStatus(ctx context.Context, t *testing.T, o *Owned, fpr, want string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		got := contactStatus(ctx, t, o, fpr)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s holds %s as %q, want %q", o.Node.Name, fpr, got, want)
		}
		time.Sleep(2 * time.Second)
	}
}

// send is the owner's send_to_contact; nil means the node answered it as sent.
func send(ctx context.Context, o *Owned, fpr, text string) error {
	_, err := o.Owner.Call(ctx, "send_to_contact", map[string]any{
		"account_id": o.AccountID, "contact_fpr": fpr, "text": text, "msg_id": "S21-" + text,
	})
	return err
}

// inboxHas reports whether any conversation in the owner's inbox carries text, reading every
// thread the inbox lists.
func inboxHas(ctx context.Context, t *testing.T, o *Owned, text string) bool {
	t.Helper()
	raw, err := o.Owner.Call(ctx, "get_inbox", map[string]any{"account_id": o.AccountID})
	if err != nil {
		t.Fatalf("get_inbox: %v", err)
	}
	if strings.Contains(raw, text) {
		return true
	}
	var threads []struct {
		ID       string `json:"id"`
		ThreadID string `json:"thread_id"`
	}
	_ = json.Unmarshal([]byte(raw), &threads)
	for _, th := range threads {
		id := th.ThreadID
		if id == "" {
			id = th.ID
		}
		if id == "" {
			continue
		}
		msgs, err := o.Owner.Call(ctx, "read_thread", map[string]any{"account_id": o.AccountID, "thread_id": id})
		if err == nil && strings.Contains(msgs, text) {
			return true
		}
	}
	return false
}

// refused reports whether a tool's successful answer is a refusal in its body ({"code": …}).
func refused(raw string) bool {
	var a struct{ Code string }
	return json.Unmarshal([]byte(raw), &a) == nil && a.Code != ""
}

// scopedToken mints an owner token limited to one account.
func scopedToken(ctx context.Context, t *testing.T, w *World, o *Owned, accountID string) string {
	t.Helper()
	ownerID := strings.TrimPrefix(field(execS(ctx, w.Fab, o.Node, "/pact-gateway", "passkey", "list"), "owner="), "owner=")
	for _, l := range strings.Split(execS(ctx, w.Fab, o.Node,
		"/pact-gateway", "token", "create", "-owner", ownerID, "-label", "scoped", "-account", accountID), "\n") {
		if strings.Contains(l, "shown once") {
			return strings.TrimSpace(l[strings.LastIndex(l, ":")+1:])
		}
	}
	t.Fatalf("no scoped token from %s", o.Node.Name)
	return ""
}

package ownermcp

import (
	"context"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

// Passkeys are the owner's, not an account's (SPEC §3.1, §8.6). A token narrowed to one account
// (SPEC §3.4) administers that account alone, so it may neither list nor remove them: the same
// refusal every account-scoped tool answers, and the same row the audit middleware writes for one.
// The control is a token that is not narrowed.
func TestPasskeyToolsRefuseANarrowedToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var removed, logged []string
	extra := Extra{
		Passkeys: func(context.Context) ([]auth.PasskeyInfo, error) {
			return []auth.PasskeyInfo{{ID: "pk-1", OwnerID: e.owner, Tag: "laptop"}, {ID: "pk-2", OwnerID: e.owner, Tag: "phone"}}, nil
		},
		RemovePasskey: func(_ context.Context, id string) error {
			removed = append(removed, id)
			return nil
		},
		Log: func(action, resource, outcome string) { logged = append(logged, action+" "+resource+" "+outcome) },
	}

	narrowed := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner, AccountID: e.acctA})
	if body := callParity(t, ctx, narrowed, "list_passkeys", map[string]any{}); !strings.Contains(body, `"code":"permission_denied"`) {
		t.Errorf("a token narrowed to one account listed the owner's passkeys: %s", body)
	}
	if body := callParity(t, ctx, narrowed, "remove_passkey", map[string]any{"id": "pk-1"}); !strings.Contains(body, `"code":"permission_denied"`) {
		t.Errorf("a token narrowed to one account was answered %s for remove_passkey", body)
	}
	if len(removed) != 0 {
		t.Errorf("a token narrowed to one account removed %v", removed)
	}
	for _, want := range []string{"owner_mcp_call tool:list_passkeys refused", "owner_mcp_call tool:remove_passkey refused"} {
		if !hasRow(logged, want) {
			t.Errorf("no row %q: %v", want, logged)
		}
	}
	if hasRow(logged, "passkey_remove") {
		t.Errorf("a refusal by scope was audited as an act on the passkey: %v", logged)
	}

	logged = nil
	whole := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner})
	if body := callParity(t, ctx, whole, "list_passkeys", map[string]any{}); !strings.Contains(body, `"id":"pk-1"`) || !strings.Contains(body, `"tag":"phone"`) {
		t.Errorf("the owner's own token could not list the passkeys: %s", body)
	}
	if body := callParity(t, ctx, whole, "remove_passkey", map[string]any{"id": "pk-1"}); !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("the owner's own token could not remove a passkey: %s", body)
	}
	if len(removed) != 1 || removed[0] != "pk-1" {
		t.Errorf("removed %v, want pk-1", removed)
	}
	if !hasRow(logged, "passkey_remove passkey:pk-1 ok") {
		t.Errorf("the removal left no row of its own: %v", logged)
	}
}

// remove_passkey's two refusals from the passkey service: the last passkey stays (auth.ErrLastPasskey,
// or zero passkeys re-open the wizard), and an id that names none is not found.
func TestRemovePasskeyAnswersTheLastOneAndAnUnknownOne(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var logged []string
	extra := Extra{
		RemovePasskey: func(_ context.Context, id string) error {
			switch id {
			case "last":
				return auth.ErrLastPasskey
			case "nope":
				return auth.ErrNoSuchPasskey
			}
			return nil
		},
		Log: func(action, resource, outcome string) { logged = append(logged, action+" "+resource+" "+outcome) },
	}
	srv := NewServerWithExtra(e.deps, extra, auth.Identity{OwnerID: e.owner})

	body := callParity(t, ctx, srv, "remove_passkey", map[string]any{"id": "last"})
	if !strings.Contains(body, `"code":"bad_request"`) || !strings.Contains(body, "only passkey") {
		t.Errorf("removing the last passkey: %s", body)
	}
	if !hasRow(logged, "passkey_remove passkey:last refused_last") {
		t.Errorf("no refused_last row: %v", logged)
	}

	body = callParity(t, ctx, srv, "remove_passkey", map[string]any{"id": "nope"})
	if !strings.Contains(body, `"code":"not_found"`) {
		t.Errorf("removing a passkey that does not exist: %s", body)
	}
	if !hasRow(logged, "passkey_remove passkey:nope not_found") {
		t.Errorf("no not_found row: %v", logged)
	}
	if hasRow(logged, "passkey_remove passkey:nope error") {
		t.Errorf("an id that names no passkey was audited as a failure: %v", logged)
	}
}

func hasRow(rows []string, prefix string) bool {
	for _, r := range rows {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

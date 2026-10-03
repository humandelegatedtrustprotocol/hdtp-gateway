package ownermcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/contacts"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/internalui/auth"
)

type failingRevoke struct{ store.Store }

func (failingRevoke) RevokeInvite(context.Context, string, string, int64) error {
	return errors.New("database is locked")
}

// revoke_invite said "no live invite with that id" for every error, so a store fault told the agent
// the invite did not exist (review of #22, finding 3). Only ErrNotFound is not_found.
func TestRevokeInviteSaysNotFoundOnlyWhenItIsNot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, inv, err := e.deps.Contacts.CreateInvite(ctx, e.acctA, contacts.InviteOptions{Label: "x"})
	if err != nil {
		t.Fatal(err)
	}
	e.deps.Store = failingRevoke{e.st}
	cs, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	out, isErr := callJSON(t, cs, "revoke_invite", map[string]any{"account_id": e.acctA, "invite_id": inv.ID})
	if !isErr || strings.Contains(out, "not_found") || !strings.Contains(out, `"internal"`) {
		t.Fatalf("a store failure: %s", out)
	}
	e.deps.Store = e.st
	cs2, _ := connect(t, e, auth.Identity{OwnerID: e.owner}, nil)
	if out, isErr := callJSON(t, cs2, "revoke_invite", map[string]any{"account_id": e.acctA, "invite_id": "no-such-invite"}); !isErr || !strings.Contains(out, "not_found") {
		t.Fatalf("a missing invite (the control): %s", out)
	}
}

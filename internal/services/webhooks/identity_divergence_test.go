package webhooks

import (
	"context"
	"encoding/json"
	"testing"
)

// A divergence from the cloud, named where a test holds it (README, "Divergences from the
// cloud"): the envelope's identity is the account's id, where the cloud sends the identity's slug
// (batondeck/gateway/src/identity/identity.ts, the event it hands to enqueueEvent). Every owner MCP
// tool of the node takes an account id, so a slug would make a receiver look the account up
// first. A node that sends the slug takes this entry out, and the README's with it.
func TestTheEnvelopesIdentityIsTheAccountIDWhereTheCloudSendsTheSlug(t *testing.T) {
	f := newFixture(t)
	rc := newReceiver(t, nil)
	f.create(t, rc.URL+"/hook")
	f.received(t, f.mine, "m1")
	f.dispatcher(nil).Pass(context.Background())

	got := rc.posts()
	if len(got) != 1 {
		t.Fatalf("%d posts, want 1", len(got))
	}
	var env struct {
		Identity string `json:"identity"`
	}
	if err := json.Unmarshal([]byte(got[0].body), &env); err != nil {
		t.Fatal(err)
	}
	a, err := f.st.GetAccountByID(context.Background(), f.mine)
	if err != nil {
		t.Fatal(err)
	}
	if env.Identity != a.ID || env.Identity == a.Slug {
		t.Fatalf("identity %q; want the account's id %q, not its slug %q", env.Identity, a.ID, a.Slug)
	}
}

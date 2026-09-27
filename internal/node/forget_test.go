package node

import (
	"testing"

	"github.com/pact-cloud/pact-gateway/internal/core/store"
)

// An identity that left this host is forgotten everywhere the node lists accounts, including the
// two lists stopServing leaves it in: awaiting a leaf, and unavailable. A slug still in either is
// named by `serve` and the portal as an account this node holds, which it no longer does.
func TestForgetAccountLeavesNoTraceInTheLiveNode(t *testing.T) {
	rec := store.Account{ID: "id-a", Slug: "alice"}
	n := &Node{
		accounts:    map[string]*account{"id-a": {rec: rec}, "id-b": {rec: store.Account{ID: "id-b", Slug: "bob"}}},
		bySlug:      map[string]*account{"alice": {rec: rec}},
		byHost:      map[string]*account{"a.example": {rec: rec}},
		awaiting:    map[string]struct{}{"alice": {}, "carol": {}},
		unavailable: map[string]string{"alice": "key will not open"},
	}
	n.ForgetAccount("id-a", "alice")
	if _, ok := n.accounts["id-a"]; ok {
		t.Error("still in accounts")
	}
	if _, ok := n.bySlug["alice"]; ok {
		t.Error("still in bySlug")
	}
	if len(n.byHost) != 0 {
		t.Errorf("still in byHost: %v", n.byHost)
	}
	if got := n.AwaitingLeaf(); len(got) != 1 || got[0] != "carol" {
		t.Errorf("awaiting a leaf: %v, want only carol", got)
	}
	if len(n.Unavailable()) != 0 {
		t.Errorf("unavailable: %v", n.Unavailable())
	}
	if _, ok := n.accounts["id-b"]; !ok {
		t.Error("bob was forgotten with alice")
	}
}

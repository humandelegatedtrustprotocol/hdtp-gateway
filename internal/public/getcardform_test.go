package public

import (
	"context"
	"testing"
	"time"

	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// The form a sealed answer carries the node's own proof in (HDTP §13.2): the chain until this
// contact has seen the node's current leaf, the fingerprint after — except for get_card's answer,
// which carries the chain whatever the record says. get_card is what a caller asks BECAUSE it could
// not verify an answer, and a caller in that state is one the record is wrong about: it says the
// chain went, and the caller never pinned it. An answer that followed the record would fail the
// same way, and nothing in the protocol would get the caller out of it until the leaf retired.
func TestGetCardIsAnsweredWithTheChainOnceTheContactHasSeenIt(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	withID := func(id string) sealOpt { return func(o *hdtpidentity.SealOpts) { o.MsgID = id } }

	// Nothing recorded yet: the first answer carries the chain, and the node records that it went.
	res := s.call(t, s.sealFrom(t, p, "chain", "send_message", map[string]any{"text": "one"}), TransportFacts{})
	if form := s.unsealed(t, res, p, msgIDFor("send_message", "chain")).Form; form != "chain" {
		t.Fatalf("the first answer to a contact carried %q, want the chain", form)
	}
	// The control: the record stands, so the next answer names the leaf.
	res = s.call(t, s.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "two"}, withID("m-two")), TransportFacts{})
	if form := s.unsealed(t, res, p, "m-two").Form; form != "leaf" {
		t.Fatalf("an answer to a contact that has seen the chain carried %q, want the leaf", form)
	}
	// get_card: the chain, whatever the record says.
	res = s.call(t, s.sealFrom(t, p, "leaf", "get_card", nil), TransportFacts{})
	if form := s.unsealed(t, res, p, msgIDFor("get_card", "leaf")).Form; form != "chain" {
		t.Fatalf("get_card's answer carried %q, want the chain (HDTP §13.2: get_card always answers with the chain)", form)
	}
	// And the record is what it was: the answer after names the leaf again.
	res = s.call(t, s.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "three"}, withID("m-three")), TransportFacts{})
	if form := s.unsealed(t, res, p, "m-three").Form; form != "leaf" {
		t.Fatalf("the answer after get_card carried %q, want the leaf: get_card's chain is not a renewal", form)
	}
}

// A contact whose first sealed call is get_card is answered with the chain, and that answer is
// recorded as the chain sent like any other chain-form answer: the answer to its next call names the
// leaf. An answer that carried the chain without being recorded would leave the contact receiving
// the chain on every call until something else carried it.
func TestAFreshContactsGetCardIsRecordedAsTheChainSent(t *testing.T) {
	s := newSealedEnv(t)
	p := newPeer(t, s.nowAt.Add(-time.Hour))
	s.pin(t, p, "active")
	ctx := context.Background()
	if c, err := s.st.GetContact(ctx, s.acct.ID, p.fpr()); err != nil || c.ChainSentKid != "" {
		t.Fatalf("a fresh contact has a chain recorded as sent: %q (%v)", c.ChainSentKid, err)
	}

	res := s.call(t, s.sealFrom(t, p, "chain", "get_card", nil), TransportFacts{})
	if form := s.unsealed(t, res, p, msgIDFor("get_card", "chain")).Form; form != "chain" {
		t.Fatalf("get_card's answer to a fresh contact carried %q, want the chain", form)
	}
	if c, _ := s.st.GetContact(ctx, s.acct.ID, p.fpr()); c.ChainSentKid != s.currentKey(t).Fingerprint {
		t.Fatalf("get_card's chain-form answer was not recorded as the chain sent: %q", c.ChainSentKid)
	}
	res = s.call(t, s.sealFrom(t, p, "leaf", "send_message", map[string]any{"text": "after the card"}), TransportFacts{})
	if form := s.unsealed(t, res, p, msgIDFor("send_message", "leaf")).Form; form != "leaf" {
		t.Fatalf("the answer after get_card carried %q, want the leaf: the chain went with get_card's answer", form)
	}
}

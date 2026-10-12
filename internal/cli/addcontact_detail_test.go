package cli

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
	hdtpidentity "github.com/humandelegatedtrustprotocol/hdtp-identity/go"
)

// What add_contact refuses is the node's own sentence, marked so the owner MCP answers it as
// bad_request with the sentence alone (refusal.Sentence); the error behind it — a dial, a peer —
// stays off that wire and off the portal's page. Error() keeps its old text, cause included. These
// errors were plain fmt.Errorf values, which the owner MCP could not tell from a store's.
func TestAddContactRefusalsAreMarkedSentences(t *testing.T) {
	ctx := context.Background()
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL + "/i/tok"
	down.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer broken.Close()

	_, _, errScheme := splitInviteURL("http://peer.example/i/tok")
	_, errDial := fetchOffer(ctx, http.DefaultClient, downURL)
	_, errStatus := fetchOffer(ctx, http.DefaultClient, broken.URL+"/i/tok")
	_, errBoth := (&contactInitiator{}).Add(ctx, "a", "https://peer.example/i/tok", "card", "", "")
	for _, c := range []struct {
		name      string
		err       error
		sentence  string
		fullStart string
	}{
		{"a link that is not https", errScheme, "an invite link is an https:// URL", "an invite link is an https:// URL"},
		{"a link that does not answer", errDial, "could not reach the invite link", "could not reach the invite link: "},
		{"a link that answers 500", errStatus, "the invite link answered HTTP 500", "the invite link answered HTTP 500"},
		{"a link and a card", errBoth, "an invite link or a card, not both", "an invite link or a card, not both"},
	} {
		got, ok := refusal.Sentence(c.err)
		if !ok || got != c.sentence {
			t.Errorf("%s: sentence %q (marked %v), want %q; error %v", c.name, got, ok, c.sentence, c.err)
		}
		if c.err == nil || !strings.HasPrefix(c.err.Error(), c.fullStart) {
			t.Errorf("%s: Error() is %v, want it to start %q", c.name, c.err, c.fullStart)
		}
	}
	if !strings.Contains(errDial.Error(), "127.0.0.1") {
		t.Errorf("the dial's own text is no longer behind the sentence in Error(): %v", errDial)
	}
	// The control: a well-formed link is no refusal.
	if _, tok, err := splitInviteURL("https://peer.example/i/tok"); err != nil || tok != "tok" {
		t.Errorf("a well-formed link was refused: %q, %v", tok, err)
	}
}

// An invite's refusals carry the node's words and nothing of the identity core's or a library's
// reasons: a chain refused by a rule names the rule alone, a card that does not read and a
// signature that does not verify say so in fixed sentences. The chain's sentence carried the core's
// reason, and the card's the core's error text. The control, a good offer, verifies.
func TestAnInviteIsRefusedInTheNodesWords(t *testing.T) {
	p := newTestPeer(t, "Alina Rao", "https://agent.alina.example/mcp")
	other := newTestPeer(t, "Someone Else", "https://agent.alina.example/mcp")
	if _, _, _, err := verifyOffer(offerFor(t, p, "Alina Rao")); err != nil {
		t.Fatalf("the control: %v", err)
	}
	expired := offerFor(t, p, "Alina Rao")
	hostKey, err := hdtpidentity.GenerateKey("p256")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf, err := hdtpidentity.BuildLeaf(hdtpidentity.LeafOpts{
		CN: p.Wallet.CN, RootCN: p.Wallet.CN, RootKey: p.Wallet.Key, HostPub: hostKey.Public(),
		URIs: []string{p.Endpoint}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	card, err := hdtpidentity.EncodeCard("Alina Rao", leaf, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hdtpidentity.SignDetached(hostKey, []byte(card))
	if err != nil {
		t.Fatal(err)
	}
	expired.Card, expired.CardSig = card, base64.RawURLEncoding.EncodeToString(sig)
	expired.Chain = []string{hdtpidentity.B64url(leaf), hdtpidentity.B64url(p.Wallet.RootDER)}

	forged := offerFor(t, p, "Alina Rao")
	fsig, err := hdtpidentity.SignDetached(other.Host.Key, []byte(forged.Card))
	if err != nil {
		t.Fatal(err)
	}
	forged.CardSig = base64.RawURLEncoding.EncodeToString(fsig)

	for _, c := range []struct {
		name string
		off  inviteOffer
		want *regexp.Regexp
	}{
		{"an expired leaf", expired, regexp.MustCompile(`^the invite's chain is refused by rule \d+$`)},
		{"a signature by another key", forged, regexp.MustCompile(`^the invite's card: the card signature does not verify$`)},
		{"a card with no certificate", inviteOffer{Card: "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Nobody\r\nX-HDTP-VERSION:1\r\nEND:VCARD\r\n"},
			regexp.MustCompile(`^the invite's card: the card's certificate is not one this node accepts$`)},
	} {
		_, _, _, err := verifyOffer(c.off)
		got, ok := refusal.Sentence(err)
		if !ok || !c.want.MatchString(got) {
			t.Errorf("%s: %v (sentence %q, marked %v), want %s", c.name, err, got, ok, c.want)
		}
	}
}

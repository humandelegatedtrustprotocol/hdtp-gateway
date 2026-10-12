package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/refusal"
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

package internalui

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// The wallet pages' buttons keep the one rule for a button (web/src/style.css `.acts`, and pact-cloud's
// gateway/e2e/layout/action-rows.mjs, which holds the portals to it in a browser): a few words, never a
// sentence and never an address. The ask page's replace button read "Replace it and continue to my
// wallet", and the submit page's "Continue to https://wallet.pact-cloud.com", which wrapped onto two
// lines on a phone; the address is now a line of its own.
const walletButtonMax = 32

var buttonText = regexp.MustCompile(`(?s)<button[^>]*>(.*?)</button>`)

func buttonsOf(t *testing.T, html string) []string {
	t.Helper()
	var out []string
	for _, m := range buttonText.FindAllStringSubmatch(html, -1) {
		out = append(out, strings.Join(strings.Fields(m[1]), " "))
	}
	if len(out) == 0 {
		t.Fatalf("no button on the page:\n%s", html)
	}
	return out
}

func TestWalletPageButtonsAreAFewWords(t *testing.T) {
	const wallet = "https://wallet-for-the-international-consortium.pact-cloud.example"
	var ask, askPending, submit strings.Builder
	base := map[string]any{"Name": "Sumit", "Endpoint": "https://sumit.example/sumit", "Purpose": "renew", "Wallet": wallet, "Slug": "sumit", "CSRF": "x"}
	if err := walletAskTmpl.Execute(&ask, base); err != nil {
		t.Fatal(err)
	}
	pending := map[string]any{}
	for k, v := range base {
		pending[k] = v
	}
	pending["Pending"] = agoWords(17 * time.Minute)
	if err := walletAskTmpl.Execute(&askPending, pending); err != nil {
		t.Fatal(err)
	}
	if err := walletSubmitTmpl.Execute(&submit, map[string]any{"Action": wallet + "/sign", "Fields": []walletField{{"code", "c"}}, "Wallet": wallet}); err != nil {
		t.Fatal(err)
	}
	for page, html := range map[string]string{"ask": ask.String(), "ask with a request waiting": askPending.String(), "submit": submit.String()} {
		for _, b := range buttonsOf(t, html) {
			if len([]rune(b)) > walletButtonMax {
				t.Errorf("%s: the button %q is %d characters, over %d", page, b, len([]rune(b)), walletButtonMax)
			}
			if strings.Contains(b, "://") {
				t.Errorf("%s: the button %q carries an address", page, b)
			}
		}
	}
	// The address the button used to carry is still said, beside it.
	if !strings.Contains(submit.String(), "Your wallet is at "+wallet) {
		t.Error("submit: the wallet's address is no longer on the page")
	}
}

func TestAgoWordsSaysHowLongAgoInWords(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second: "moments ago",
		time.Minute:      "a minute ago",
		17 * time.Minute: "17 minutes ago",
		time.Hour:        "an hour ago",
		3 * time.Hour:    "3 hours ago",
	} {
		if got := agoWords(d); got != want {
			t.Errorf("agoWords(%v) = %q, want %q", d, got, want)
		}
	}
}

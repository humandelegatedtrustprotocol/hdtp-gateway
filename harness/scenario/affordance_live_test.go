package scenario

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/harness/images"
	"github.com/tech-sumit/pact-gateway/harness/portal"
)

// Everything an owner must be able to DO from the portal, checked on a real node.
//
// Seven defects in one evening had the same shape: a working endpoint with no way
// for a person to reach it — pages the dashboard linked to that answered 404, an
// invite rendered as a path nobody could open, a logout route no button posted to,
// a header on one page out of thirteen, redeeming an invite that existed only on
// the agent surface, and an integration that could be created empty and never
// removed. Every one had a passing test that called the endpoint directly.
//
// So this asserts the affordances, not the endpoints. It is the check that would
// have caught all seven.
//
// It asserts them on the page a browser DRAWS, as the signed-in owner. It used to fetch each
// path and look for `action="/invites/create"` in the HTML, which was right while the server
// rendered pages. The portal is one page over a JSON API now and requires a session on every
// bind (SPEC §8.3): the document behind every path is the same empty shell, so that fetch found
// none of its forms — and said nothing, because a live scenario is skipped unless asked for.
func TestPortalOffersEveryAffordanceAnOwnerNeeds(t *testing.T) {
	requireLive(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	p, err := SetupPaired(ctx, "pactaff", Ports{Owner: "18661", Public: "18662"}, images.Node)
	t.Cleanup(func() { p.Teardown(os.Getenv("PACT_HARNESS_ARTIFACTS")) })
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	br, err := p.Portal.Browser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	base := p.Portal.Base
	see := func(path string) portal.Page {
		t.Helper()
		pg, err := br.Rendered(ctx, base+path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return pg
	}
	offers := func(pg portal.Page, control string) bool {
		for _, c := range pg.Controls {
			if strings.Contains(strings.ToLower(c), strings.ToLower(control)) {
				return true
			}
		}
		return false
	}

	// 1. The shell is on EVERY page the dashboard offers, and every one of them is a page.
	for _, href := range portalLinks(t, see("/")) {
		pg := see(href)
		if strings.Contains(pg.Text, "Nothing lives at") {
			t.Errorf("%s: the dashboard links to a page that does not exist", href)
			continue
		}
		if !pg.HasNav {
			t.Errorf("%s renders with no shell: nothing to navigate with, no way out", href)
		}
	}

	// 2. An invite can be made.
	if pg := see("/invites"); !strings.Contains(pg.Text, "Create an invite") || !offers(pg, "Create") {
		t.Errorf("no way to create an invite: %v", pg.Controls)
	}

	// 3. Accepting somebody else's invite — the direction that once existed only on the owner MCP.
	if pg := see("/contacts"); !offers(pg, "Accept invite") || !offers(pg, "their.node/i/") {
		t.Errorf("no way to accept an invite from Contacts: %v", pg.Controls)
	}
	// ...and asking from a card held out of band, SPEC §9.3's import (review N-17).
	if pg := see("/contacts"); !offers(pg, "Ask to connect") {
		t.Errorf("no way to connect from a card on Contacts: %v", pg.Controls)
	}

	// 4. Integrations: junk cannot be created, and what exists can be removed.
	if pg := see("/integrations"); !offers(pg, "Add integration") {
		t.Errorf("no way to add an integration: %v", pg.Controls)
	}
	// An empty submission must be refused rather than creating a row that shows as
	// `— streamable-http — disabled` and can never be removed.
	if err := p.Portal.PostForm(ctx, "/integrations/create", p.AccountID, map[string]string{
		"transport": "streamable-http",
	}); err == nil {
		t.Error("an integration with no slug and nothing to dial was accepted")
	}
	if err := p.Portal.PostForm(ctx, "/integrations/create", p.AccountID, map[string]string{
		"slug": "probe", "transport": "streamable-http",
		"endpoint": "https://example.invalid/mcp", "auth_kind": "none",
	}); err != nil {
		t.Fatalf("a valid integration was refused: %v", err)
	}
	if pg := see("/integrations"); !strings.Contains(pg.Text, "probe") || !offers(pg, "Remove probe") {
		t.Errorf("an integration cannot be removed: %v", pg.Controls)
	}

	// 5. Messaging has a way IN. It worked end to end and could only be reached from a thread
	//    that already existed, so an owner could reply and never start a conversation.
	contact := url.QueryEscape(p.Contact.Fingerprint())
	if pg := see("/messages"); !offers(pg, "bob") {
		t.Errorf("the conversation view lists no contact to talk to: %v", pg.Controls)
	}
	if pg := see("/messages?contact=" + contact); !offers(pg, "Message") || !offers(pg, "Send") {
		t.Errorf("picking a contact offers nowhere to write and nothing to send with: %v", pg.Controls)
	}

	// 6. And a conversation can be ENDED, not only started — and their card re-fetched, for
	//    this one contact (the button R3 added; there is no control that refreshes more).
	pg := see("/contacts/" + contact)
	if !offers(pg, "Remove contact") {
		t.Errorf("a contact cannot be removed: %v", pg.Controls)
	}
	if !offers(pg, "Refresh now") {
		t.Errorf("a contact's card cannot be refreshed: %v", pg.Controls)
	}

	t.Log("portal: every page wears the shell, invites can be created and accepted, " +
		"integrations are validated and removable, conversations can be started and ended")
}

// portalLinks is the in-portal links a drawn page offers.
func portalLinks(t *testing.T, pg portal.Page) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	for _, href := range pg.Links {
		// in-portal pages only: not the .vcf download, not an external link
		if !strings.HasPrefix(href, "/") || strings.Contains(href, ".vcf") || seen[href] {
			continue
		}
		seen[href] = true
		out = append(out, href)
	}
	if len(out) < 5 {
		t.Fatalf("only %d links on the dashboard; the page is not what we think it is: %v", len(out), pg.Links)
	}
	return out
}

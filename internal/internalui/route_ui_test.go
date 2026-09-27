package internalui

// Every mutating route the portal serves must be reachable from the portal.
//
// TestEveryAgentCapabilityHasAPortalAffordance asks the other question — can a
// person do what the agent can — and it is one-directional. It cannot see a
// route that the SERVER offers and the UI never calls, which is how two real
// capabilities went missing when the SPA replaced the server-rendered pages:
//
//   - /media/{hash} and /media/fetch. A contact could send a file, the node
//     stored it quota-counted and content-addressed, and the conversation view
//     rendered the media row's JSON body as if it were prose. The owner saw
//     `{"filename":...}` and had nothing to click — the exact defect the thread
//     page had been fixed for once already.
//   - /settings/pair and /settings/unpair. The API sends `show_pair` and
//     `paired`; the settings view never read them, so pairing this node with an
//     ingress on your own domain was portal-shaped and portal-unreachable.
//
// Checked against web/src rather than the compiled bundle: the sources hold the
// literal paths, and a route named nowhere in them cannot be called by anything.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Routes a person is deliberately not given, each with the reason.
var uiExempt = map[string]string{
	"/login/begin":  "WebAuthn ceremony, driven by webauthn.ts rather than a page",
	"/login/finish": "as above",
	"/setup/begin":  "as above",
	"/setup/finish": "as above",
	"/setup":        "the wizard page itself, served through the §8.6 gate",
	"/threads/{id}/send": "superseded by /messages/send: the conversation view sends to a " +
		"CONTACT and lets the node pick the thread, because a conversation is with a person",
	"/identity/{slug}/wallet/start": "the form of the server-rendered page GET /identity/{slug}/wallet, " +
		"which the Identity view links to (wallet_pages.go)",
	"/identity/{slug}/wallet/install": "POSTed by /wallet/return.js, the script of the page a web wallet " +
		"navigates back to (wallet_pages.go)",
}

var postRoute = regexp.MustCompile(`"POST (/[^"]*)"`)

func TestEveryPortalRouteIsReachableFromTheUI(t *testing.T) {
	root := repoRootUI(t)

	// What the SPA's sources mention.
	var src strings.Builder
	err := filepath.WalkDir(filepath.Join(root, "web", "src"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(p, ".ts") && !strings.HasSuffix(p, ".tsx") {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		src.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ui := src.String()
	if ui == "" {
		t.Fatal("no SPA sources found; this lint is checking nothing")
	}

	var checked int
	err = filepath.WalkDir(filepath.Join(root, "internal", "internalui"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, m := range postRoute.FindAllStringSubmatch(string(b), -1) {
			route := m[1]
			if _, ok := uiExempt[route]; ok {
				continue
			}
			checked++
			if !strings.Contains(ui, reachableFragment(route)) {
				t.Errorf("%s serves POST %s and nothing in web/src calls it — the capability "+
					"exists and no person can reach it. Add the affordance, or name the route "+
					"in uiExempt with the reason.", filepath.Base(p), route)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no routes checked; the scan is looking in the wrong place")
	}
	t.Logf("checked %d mutating routes", checked)
}

// reachableFragment is the part of a route the SPA must name literally. Path
// parameters are interpolated there (`/contacts/${fpr}/petname`), so the tail
// from the last parameter onward is what survives as a literal string.
func reachableFragment(route string) string {
	if i := strings.LastIndex(route, "}"); i >= 0 {
		return route[i+1:]
	}
	return route
}

package internalui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// #221. A ticked "Accept LAN connections" saved as false: the page's checkbox posts value "1"
// (web/src/views/settings.tsx) and the save stored "true" only for a posted "true", so no bool
// knob could be turned on from the portal. The form is posted here exactly as the page renders
// it, its value read from the page's source, and the knob must read back as true on the next GET;
// unticked (absent from the form, as a browser sends it) it reads back as false.
func TestATickedSettingsCheckboxSavesAsTrue(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRootUI(t), "web", "src", "views", "settings.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`<input type="checkbox" name=\{r\.key\} value="([^"]*)"`).FindSubmatch(src)
	if m == nil {
		t.Fatal(`settings.tsx renders no <input type="checkbox" name={r.key} value="…">; this test reads the value a ticked box posts from it`)
	}
	ticked := string(m[1])

	stored := map[string]string{}
	e := newPortalEnv(t, func(mux *http.ServeMux, st store.Store) {
		MountSettingsPages(mux, SettingsDeps{Owners: st,
			Effective: func() []core.Effective {
				v := stored["lan_connections"]
				if v == "" {
					v = "false"
				}
				return []core.Effective{{Key: "lan_connections", Value: v}}
			},
			Save: func(_ context.Context, values []SettingValue) error {
				for _, v := range values {
					stored[v.Key] = v.Value
				}
				return nil
			},
			Audit: func(string, string, string) {},
		})
	})
	_, session := e.signIn(t, "Me")
	readBack := func() string {
		t.Helper()
		rr := e.do(t, http.MethodGet, "/api/settings", nil, []*http.Cookie{session})
		var page struct {
			Security []settingRow `json:"security"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &page) != nil {
			t.Fatalf("GET /api/settings: %d %s", rr.Code, rr.Body.String())
		}
		for _, r := range page.Security {
			if r.Key == "lan_connections" {
				return r.Value
			}
		}
		t.Fatalf("GET /api/settings has no lan_connections row: %s", rr.Body.String())
		return ""
	}
	for _, c := range []struct {
		name string
		form url.Values
		want string
	}{
		{"ticked, as the page posts it (value " + ticked + ")", url.Values{"lan_connections": {ticked}}, "true"},
		{"unticked, absent from the form", url.Values{}, "false"},
	} {
		code, body := e.postPage(t, "/settings", c.form, session)
		if code != http.StatusOK || body["error"] != false {
			t.Fatalf("%s: POST /settings answered %d %v", c.name, code, body)
		}
		if stored["lan_connections"] != c.want {
			t.Errorf("%s: stored %q; want %q", c.name, stored["lan_connections"], c.want)
		}
		if got := readBack(); got != c.want {
			t.Errorf("%s: GET /api/settings reads %q back; want %q", c.name, got, c.want)
		}
	}
}

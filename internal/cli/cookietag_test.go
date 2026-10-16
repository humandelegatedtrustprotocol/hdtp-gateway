package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// The portal's cookie names carry the node's tag (core.NodeTag), and a session is found by its
// cookie's name. A public URL the owner saves in the portal, or one a tunnel adapter allocates, must
// not rename the cookies at the next start, or every restart after it signs the owner out (#169).
// The tag is the configuration's as the file and the environment give it; the control is that a
// public URL in the file still names the node.
func TestThePortalCookieNameOutlivesASavedPublicURL(t *testing.T) {
	cases := []struct {
		name     string
		fileURL  string            // public_url in config.json ("" = the key is absent)
		settings map[string]string // rows saved in the portal before the start
	}{
		{"a public URL saved in the portal", "", map[string]string{"public_url": "https://saved.example.com"}},
		{"a public URL an adapter allocates", "", map[string]string{
			"tunnel": "cloudflare", "tunnel.cloudflare.hostname": "cf.example.com", "tunnel.cloudflare.sidecar": "true",
			"lan_connections": "true",
		}},
		{"control: a public URL in the file", "https://file.example.com", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			internal, public := freePort(t), freePort(t)
			cfg := map[string]any{"data_dir": dir, "internal_bind": internal, "public_bind": public, "store_engine": "sqlite"}
			if tc.fileURL != "" {
				cfg["public_url"] = tc.fileURL
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(dir, "config.json")
			if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
				t.Fatal(err)
			}
			st, err := store.OpenSQLite(filepath.Join(dir, "hdtp.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.settings {
				if err := st.PutSetting(context.Background(), store.Setting{Key: k, Value: v, UpdatedAt: time.Now().Unix()}); err != nil {
					t.Fatal(err)
				}
			}
			st.Close()

			r := startServeAt(t, dir, cfgPath, internal, public)
			res, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + r.internal + "/api/session")
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var got struct {
				CookieTag string `json:"cookie_tag"`
			}
			if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if want := core.NodeTag(dir, tc.fileURL, internal); got.CookieTag != want {
				t.Fatalf("cookie tag %q, want %q: the start renamed the portal's cookies", got.CookieTag, want)
			}
		})
	}
}

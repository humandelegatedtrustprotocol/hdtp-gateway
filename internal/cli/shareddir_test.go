package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two `serve` processes share one data dir on one host (SPEC §11.1): the second starts beside the
// first, says that the first serves the admin socket, and both answer on their own public
// listeners; an offline command is refused while either runs.
func TestTwoServesShareOneDataDir(t *testing.T) {
	first := runServe(t, func(t *testing.T, dir string) { seedAccount(t, dir, "alice") })

	internal, public := freePort(t), freePort(t)
	b, err := json.Marshal(map[string]any{
		"data_dir": first.dir, "internal_bind": internal, "public_bind": public,
		"public_url": "https://" + public, "store_engine": "sqlite", "seal": "optional", "client_cert": "preferred",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := filepath.Join(t.TempDir(), "second.json")
	if err := os.WriteFile(cfg2, b, 0o600); err != nil {
		t.Fatal(err)
	}
	second := startServeAt(t, first.dir, cfg2, internal, public)
	if !strings.Contains(second.out.String(), "is served by another pact-gateway process on this data dir") {
		t.Fatalf("the second serve did not say who serves the admin socket:\n%s", second.out.String())
	}
	if strings.Contains(first.out.String(), "is served by another") {
		t.Fatal("the first serve, alone when it started, did not take the admin socket")
	}

	for _, r := range []*running{first, second} {
		req, _ := http.NewRequest("POST", "https://"+r.public+"/a/alice/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := (&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", r.public, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", r.public, res.StatusCode)
		}
	}

	var out, errOut bytes.Buffer
	if code := migrate([]string{"--config", cfg2}, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "in use") {
		t.Fatalf("migrate ran beside two serves: %d %s", code, errOut.String())
	}
}

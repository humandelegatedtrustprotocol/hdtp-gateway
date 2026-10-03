package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// `internal_host` is the passkey relying party (SPEC §12.2), and since go-webauthn 0.18 the library
// refuses some names outright — an IP address, a single label other than `localhost`, a trailing dot.
// The node used to learn that at the first ceremony: it started cleanly, served its portal, and no
// passkey could be registered or used on it, with the reason in a log line. A config that cannot work
// is refused when it is read, by the rule's name, in the library's own judgement.
func TestAnInternalHostThatCannotBeARelyingPartyIsRefusedWhenTheConfigIsRead(t *testing.T) {
	load := func(host string) error {
		dir := t.TempDir()
		b, _ := json.Marshal(map[string]any{
			"data_dir": dir, "internal_bind": "0.0.0.0:8443", "internal_host": host, "public_bind": "127.0.0.1:0",
			"public_url": "https://hdtp.example.com", "internal_auth_enabled": true, "internal_tls_cert": "c.pem", "internal_tls_key": "k.pem",
		})
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConfig(path)
		return err
	}
	for _, host := range []string{"nas", "raspberrypi", "192.168.1.10", "hdtp.example.com.", "-hdtp.example.com", "hdtp.example.123"} {
		err := load(host)
		if err == nil || !strings.Contains(err.Error(), core.RuleInternalHostIsRPID) {
			t.Errorf("internal_host %q was accepted (or refused without naming %s): %v", host, core.RuleInternalHostIsRPID, err)
		}
	}
	for _, host := range []string{"hdtp.example.com", "HDTP.Example.com", "node.tail1234.ts.net", "localhost"} {
		if err := load(host); err != nil {
			t.Errorf("internal_host %q is a good relying party and the config was refused: %v", host, err)
		}
	}
}

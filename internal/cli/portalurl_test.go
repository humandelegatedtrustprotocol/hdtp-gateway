package cli

import (
	"strings"
	"testing"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// AC (P10-05c): the printed setup URL must be one a browser can complete a
// passkey ceremony against. It used to be "http://" + internal_bind verbatim.
func TestSetupURLIsOneABrowserCanRegisterAgainst(t *testing.T) {
	cases := []struct {
		name string
		cfg  core.Config
		want string
		warn bool
	}{
		{"loopback", core.Config{InternalBind: "127.0.0.1:8080"},
			"http://127.0.0.1:8080/setup?token=T", false},
		{"wildcard becomes loopback", core.Config{InternalBind: "0.0.0.0:8080"},
			"http://127.0.0.1:8080/setup?token=T", false},
		{"bare port becomes loopback", core.Config{InternalBind: ":8080"},
			"http://127.0.0.1:8080/setup?token=T", false},
		{"ipv6 wildcard becomes loopback", core.Config{InternalBind: "[::]:8080"},
			"http://127.0.0.1:8080/setup?token=T", false},
		{"tls means https", core.Config{InternalBind: "0.0.0.0:8443", InternalTLSCert: "/c.pem"},
			"https://127.0.0.1:8443/setup?token=T", false},
		{"internal_host wins, because passkeys bind to it",
			core.Config{InternalBind: "0.0.0.0:8443", InternalHost: "node.example", InternalTLSCert: "/c.pem"},
			"https://node.example:8443/setup?token=T", false},
		{"a LAN address over http cannot host a ceremony",
			core.Config{InternalBind: "192.168.1.10:8080", InternalHost: "192.168.1.10"},
			"http://192.168.1.10:8080/setup?token=T", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := setupURL(&c.cfg, "T")
			if got != c.want {
				t.Errorf("setupURL = %q, want %q", got, c.want)
			}
			if strings.Contains(got, "http:///") || strings.Contains(got, "0.0.0.0") || strings.Contains(got, "[::]") {
				t.Errorf("printed a URL no browser can open: %q", got)
			}
			warned := secureContextWarning(&c.cfg) != ""
			if warned != c.warn {
				t.Errorf("secure-context warning = %v, want %v (url %q)", warned, c.warn, got)
			}
		})
	}
}

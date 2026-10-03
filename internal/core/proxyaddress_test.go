package core

import (
	"strings"
	"testing"
)

// proxy_address names the one proxy whose forwarded chain and address the listener reads (SPEC
// §5.1): an IP address, from the environment or the file, and nothing else. A name would have to be
// resolved to compare a connection's source with it, and a resolver is not a thing a caller's
// identity should hang on.
func TestTheProxyAddressIsAnIPAddress(t *testing.T) {
	for _, ok := range []string{"172.30.40.10", "2001:db8::7"} {
		c, err := load(t, "", map[string]string{"HDTP_PROXY_ADDRESS": ok})
		if err != nil || c.ProxyAddress != ok {
			t.Errorf("HDTP_PROXY_ADDRESS=%s: %v, read %q", ok, err, c.ProxyAddress)
		}
	}
	c, err := load(t, "", nil)
	if err != nil || c.ProxyAddress != "" {
		t.Fatalf("with none configured: %v, read %q (no proxy is trusted by default)", err, c.ProxyAddress)
	}
	for _, bad := range []string{"envoy", "172.30.40.10:8443", "172.30.40.0/24", " "} {
		if _, err := load(t, "", map[string]string{"HDTP_PROXY_ADDRESS": bad}); err == nil || !strings.Contains(err.Error(), RuleProxyAddress) {
			t.Errorf("HDTP_PROXY_ADDRESS=%q: %v, want %s", bad, err, RuleProxyAddress)
		}
	}
	if _, err := load(t, `{"proxy_address":"envoy"}`, nil); err == nil || !strings.Contains(err.Error(), RuleProxyAddress) {
		t.Errorf("proxy_address in the file: %v, want %s", err, RuleProxyAddress)
	}
}

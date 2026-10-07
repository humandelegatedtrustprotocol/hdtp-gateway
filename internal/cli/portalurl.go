package cli

// The address an owner types to reach the portal (SPEC §12.4, §8.3).
//
// This used to be `"http://" + cfg.InternalBind`, which produced a URL a browser
// cannot register a passkey against in three separate situations:
//
//   - a wildcard bind (`:8080`, `0.0.0.0:8080`) yields `http:///setup` or a
//     host that routes nowhere;
//   - a TLS-configured portal is `https`, and printing `http` sends the owner to
//     a port that speaks TLS;
//   - WebAuthn requires a SECURE CONTEXT. `http` is only trusted on loopback, so
//     an owner told to visit `http://192.168.1.10:8080/setup` reaches a page
//     whose `navigator.credentials.create` the browser refuses outright.
//
// The hostname also decides the relying party a credential binds to, so
// `internal_host` — when set — is the name that must appear here (§12.2).

import (
	"net"
	"strings"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core"
)

// portalBase is the scheme://host:port an owner should open.
func portalBase(cfg *core.Config) string {
	scheme := "http"
	if cfg.InternalTLSCert != "" {
		scheme = "https"
	}
	host, port, err := net.SplitHostPort(cfg.InternalBind)
	if err != nil {
		host, port = cfg.InternalBind, ""
	}
	switch {
	case cfg.InternalHost != "":
		// The name passkeys bind to wins: a credential registered against a bare
		// IP will not work once the owner uses the hostname (§12.2).
		host = cfg.InternalHost
	case host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" || isLoopbackIP(host):
		// A wildcard bind is not an address, and a loopback IP is not a relying-party ID: the
		// portal registers and accepts passkeys on loopback only as `localhost`
		// (internalui.OriginPolicy.RelyingParty), so that is the name printed. It is a secure
		// context, so the ceremony can actually run.
		host = "localhost"
	}
	if port != "" && !strings.Contains(host, ":") {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	return scheme + "://" + host
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// setupURL is the one-time first-run/lockout link (§3.1, §12.4).
func setupURL(cfg *core.Config, token string) string {
	return portalBase(cfg) + "/setup?token=" + token
}

// secureContextWarning returns advice when the printed URL cannot host a
// WebAuthn ceremony, or "" when it can. Saying nothing would leave an owner
// staring at a button that silently does nothing.
func secureContextWarning(cfg *core.Config) string {
	if cfg.InternalTLSCert != "" {
		return ""
	}
	base := portalBase(cfg)
	host := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.IsLoopback() {
		return ""
	}
	if host == "localhost" {
		return ""
	}
	return "note: browsers only allow passkey registration over https or on " +
		"loopback. Open this URL from the node's own machine, or set " +
		"internal_tls_cert/internal_tls_key so the portal serves https."
}

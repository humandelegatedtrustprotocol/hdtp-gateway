package internalui

// Which relying party a WebAuthn ceremony runs under (SPEC §8.3).
//
// The browser derives a credential's RP ID hash from the origin it is on, so the
// relying party cannot be fixed when the process starts: a portal on
// `localhost:8080` and the same portal on `pact.example.com` are different
// relying parties, and a credential made for one does not work on the other.
//
// It also cannot simply be read from the request. `Host` is attacker-controlled:
// honoring it unvalidated would let a spoofed header bind a credential to a
// domain the owner does not control. So the host is matched against an
// allow-list — loopback names, plus the one hostname configured at startup.

import (
	"net"
	"net/http"
	"strings"

	"github.com/tech-sumit/pact-gateway/internal/internalui/auth"
)

// OriginPolicy decides the relying party for a request.
type OriginPolicy struct {
	// InternalHost is the configured non-loopback hostname; "" allows only
	// loopback.
	InternalHost string
	// TLS reports whether the portal is served over https.
	TLS bool
}

// loopbackNames are always acceptable: they are unspoofable in the sense that
// matters — a request that really reached a loopback listener came from this
// machine, and `localhost` is a valid RP ID.
func loopbackNames(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "[::1]", "::1":
		return true
	}
	return net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

// RelyingParty resolves the RP for this request, or false if the Host is not one
// this node will bind credentials to.
func (p OriginPolicy) RelyingParty(r *http.Request) (auth.RelyingParty, bool) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	switch {
	case p.InternalHost != "" && host == strings.ToLower(p.InternalHost):
		// A registrable domain: RP ID is the host itself, so a credential
		// stays valid across ports and paths on that name.
	case loopbackNames(host):
		// `127.0.0.1` is NOT a registrable suffix of `localhost`, and an IP is
		// not a valid RP ID — so a loopback portal always presents itself as
		// `localhost`, and the RP ID matches only when the browser is on that
		// name. This is the pairing the previous fixed configuration got wrong.
		if host != "localhost" {
			return auth.RelyingParty{}, false
		}
	default:
		return auth.RelyingParty{}, false
	}

	scheme := "http"
	if p.TLS || r.TLS != nil {
		scheme = "https"
	}
	return auth.RelyingParty{ID: host, Origin: scheme + "://" + r.Host}, true
}

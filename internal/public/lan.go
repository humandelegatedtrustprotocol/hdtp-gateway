package public

// The LAN connections flag (SPEC §5.1, §10.1): when a tunnel adapter is active,
// the node's own listener can still be reached directly from the local network,
// bypassing the carrier. The flag says whether that is allowed. It defaults ON
// in direct mode (a LAN caller there presents the same end-to-end mTLS surface,
// so the flag carries no security weight) and OFF in edge mode, where the
// listener is configured for edge assumptions — client certs off, identity from
// envelopes — and a LAN caller would sidestep the derivation entirely.
//
// Every refusal is audited. The flag is inert with no tunnel configured.

import (
	"net"
	"net/http"
	"strings"
)

// LANGuard refuses private-range connections when the flag is off.
type LANGuard struct {
	// Adapter is the active tunnel adapter name ("" or "direct" = inert).
	Adapter string
	// Allow mirrors the resolved config flag.
	Allow bool
	// AllowFn, when set, overrides Allow per request: the owner flips the flag
	// in the portal and the next connection is judged by the new value.
	AllowFn func() bool
	// TrustedHeader, when set (edge adapters only), names the header the real
	// source address comes from — the socket address is the connector's.
	TrustedHeader string
	Audit         func(action, resource, outcome string)
	// isPrivate is a seam for tests; nil uses the SPEC §7.5 range list.
	isPrivate func(net.IP) bool
}

func (g LANGuard) private(ip net.IP) bool {
	if g.isPrivate != nil {
		return g.isPrivate(ip)
	}
	return isPrivateAddr(ip)
}

// inert reports whether the flag applies at all.
func (g LANGuard) inert() bool {
	return g.Adapter == "" || g.Adapter == "direct" || g.allowed()
}

// Middleware wraps the public handler.
//
// The inert check happens PER REQUEST, not once at wiring time: the owner can
// flip the flag in the portal while the node serves, and a guard that decided
// its own irrelevance at startup would ignore that for the rest of the process.
func (g LANGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.inert() {
			next.ServeHTTP(w, r)
			return
		}
		// Behind a terminating edge the socket address is the connector's, so a
		// tunneled request is identified by the trusted header being present;
		// a request WITHOUT it on such a listener came straight off the LAN.
		if g.TrustedHeader != "" && strings.TrimSpace(r.Header.Get(g.TrustedHeader)) != "" {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		// Loopback is the CARRIER's own delivery, not a LAN bypass. Every reverse
		// tunnel dials the node's public bind from the node's own host — frp, ngrok
		// and tsnet in-process, cloudflared as a child — so a refused loopback
		// source meant every edge-mode deployment refused its own connector and
		// could not serve one request. A LAN host cannot present a loopback source:
		// the kernel drops 127/8 arriving on an external interface.
		//
		// It is only safe because loopback grants no authority on THIS surface —
		// the caller is still a guest without a client certificate or a sealed
		// envelope. §8.4 refuses loopback as authority for the owner MCP, where it
		// would grant everything; the asymmetry is deliberate.
		//
		// The rest of the §7.5 list — RFC 1918, unique-local, link-local, CGNAT —
		// is untouched, and `isPrivateAddr` itself is NOT changed: the media
		// fetcher's SSRF check shares it and must keep blocking loopback.
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && g.private(ip) {
			if g.Audit != nil {
				g.Audit("lan_refused", "src:"+host, "denied")
			}
			http.Error(w, `{"code":"unavailable"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isPrivateAddr is the SPEC §7.5 range list: loopback, RFC 1918, unique-local,
// link-local (incl. cloud metadata), unspecified, plus CGNAT 100.64.0.0/10.
// The `tailscale` adapter's own listener is exempt by construction: it is a
// direct-mode adapter, so the guard is inert there and its 100.64/10 addresses
// are never classified as LAN (§5.1).
func (g LANGuard) allowed() bool {
	if g.AllowFn != nil {
		return g.AllowFn()
	}
	return g.Allow
}

func isPrivateAddr(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}

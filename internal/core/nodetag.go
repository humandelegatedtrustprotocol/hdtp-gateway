package core

// NodeTag: a short, stable, non-secret name for THIS node, used to keep two
// nodes on the same host from overwriting each other's browser cookies.
//
// Cookies are scoped by host and path — never by port (RFC 6265 §8.5, and it is
// not an oversight: ports were deliberately left out of the same-origin rule for
// cookies). Two nodes on `localhost:18120` and `localhost:18121` therefore share
// one cookie jar, and whichever logged in last owns the single `hdtp_session`
// entry. The other node's owner is silently signed out, having done nothing.
//
// That is not a hypothetical: docs/demos/cloudflare-two-users.sh runs exactly
// this pair, and it made the portal look like it was dropping sessions at
// random — every "identity_required" on one node lined up with a successful
// login on the other.
//
// The tag goes in the cookie NAME, so each node keeps its own entry. It is
// derived, not stored, so it needs no migration and no state: any two nodes that
// differ in where their data lives, what they serve, or where they bind get
// different tags.

import (
	"crypto/sha256"
	"encoding/hex"
)

// NodeTag returns 8 hex characters identifying this node's configuration.
//
// It is NOT a secret and must never become one: it is visible in a cookie name.
// The inputs are chosen so that two nodes a person is likely to run side by side
// differ in at least one — separate data directories (two local nodes), or
// separate public URLs (two containers with an identical layout, which is the
// demo pair).
func NodeTag(dataDir, publicURL, internalBind string) string {
	sum := sha256.Sum256([]byte(dataDir + "\x00" + publicURL + "\x00" + internalBind))
	return hex.EncodeToString(sum[:4])
}

// Tag is NodeTag for a resolved config.
func (c *Config) Tag() string { return NodeTag(c.DataDir, c.PublicURL, c.InternalBind) }

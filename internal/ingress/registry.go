// Package ingress implements the ingress role (SPEC §10.6): a public front door
// that holds DNS and certificates for a domain and fronts paired nodes on
// subdomains — passthrough (SNI-routed raw TLS, node's own cert end to end)
// or terminate (ACME at the ingress, fresh mutually-pinned mTLS to the node).
// The data plane is the embedded frp server; the pairing + registry protocol
// is deliberately the one a hosted platform would speak.
package ingress

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Mode is a subdomain's serving mode (SPEC §10.6).
type Mode string

const (
	// ModePassthrough routes raw TLS by SNI to the node, which keeps its own certificate end to end; the ingress cannot read it.
	ModePassthrough Mode = "passthrough"
	// ModeTerminate has the ingress answer the public TLS session with its ACME certificate and open a fresh mutually pinned mTLS leg to the node.
	ModeTerminate Mode = "terminate"
)

// Node is one paired node: its identity pin, its subdomain, its mode, and the
// per-node data-plane secret minted at pairing.
type Node struct {
	// Fingerprint is the identity fingerprint of the key in the client certificate presented at pairing.
	Fingerprint string `json:"fingerprint"`
	// SPKI is that key's PKIX encoding; the terminator's onward leg accepts only a certificate carrying these bytes.
	SPKI []byte `json:"spki"`
	// Subdomain is the one DNS label the node serves, unique across the book.
	Subdomain string `json:"subdomain"`
	// Mode is the mode the node was paired in.
	Mode Mode `json:"mode"`
	// Secret is the data-plane login credential (frp metadata) minted at pairing.
	Secret string `json:"secret"`
	// PairedAt is when the ingress recorded the pairing.
	PairedAt time.Time `json:"paired_at"`
}

// Registry is the ingress's book of paired nodes and outstanding pairing
// tokens. In-memory here; the interface is the persistence seam.
type Registry interface {
	// MintToken returns a new single-use pairing token ("pair_" and 32 hex characters) valid for ttl.
	MintToken(ttl time.Duration) (string, error)
	// ConsumeToken burns a token: exactly one pairing per token. It reports false for an
	// unknown, already used or expired token; an expired one is burned too.
	ConsumeToken(token string) bool
	// Put records a pairing. It refuses a subdomain that is not one DNS label (ValidSubdomain), a
	// mode other than passthrough or terminate, and a subdomain already paired to a different
	// fingerprint; the same fingerprint on the same subdomain replaces the row.
	Put(n Node) error
	// BySubdomain returns the pairing for a subdomain.
	BySubdomain(sub string) (Node, bool)
	// ByFingerprint returns the pairing whose node has the given identity fingerprint.
	ByFingerprint(fpr string) (Node, bool)
	// All returns a copy of every pairing, in no particular order.
	All() []Node
}

type memRegistry struct {
	mu     sync.Mutex
	tokens map[string]time.Time
	nodes  map[string]Node // by subdomain
	now    func() time.Time
}

// NewMemoryRegistry returns an in-memory Registry. now is the clock for token expiry; nil means
// time.Now.
func NewMemoryRegistry(now func() time.Time) Registry {
	if now == nil {
		now = time.Now
	}
	return &memRegistry{tokens: map[string]time.Time{}, nodes: map[string]Node{}, now: now}
}

func (r *memRegistry) MintToken(ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := "pair_" + hex.EncodeToString(b)
	r.mu.Lock()
	r.tokens[tok] = r.now().Add(ttl)
	r.mu.Unlock()
	return tok, nil
}

func (r *memRegistry) ConsumeToken(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.tokens[token]
	if !ok {
		return false
	}
	delete(r.tokens, token)
	return r.now().Before(exp)
}

// InternalName is the SNI a terminate-mode node's reverse tunnel registers:
// reachable only from the ingress itself (the vhost port is loopback-scoped
// for it), carrying the fresh mutually-pinned mTLS leg (SPEC §10.6).
func InternalName(sub, domain string) string { return sub + ".internal." + domain }

// ValidSubdomain accepts one DNS label: lowercase letters, digits and hyphens, 1 to 63 bytes,
// not beginning or ending with a hyphen.
func ValidSubdomain(s string) bool {
	if s == "" || len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func (r *memRegistry) Put(n Node) error {
	if !ValidSubdomain(n.Subdomain) {
		return fmt.Errorf("ingress: subdomain %q is not a valid DNS label", n.Subdomain)
	}
	if n.Mode != ModePassthrough && n.Mode != ModeTerminate {
		return fmt.Errorf("ingress: mode %q (want passthrough|terminate)", n.Mode)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.nodes[n.Subdomain]; ok && existing.Fingerprint != n.Fingerprint {
		return fmt.Errorf("ingress: subdomain %q is already paired to another node", n.Subdomain)
	}
	r.nodes[n.Subdomain] = n
	return nil
}

func (r *memRegistry) BySubdomain(sub string) (Node, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[sub]
	return n, ok
}

func (r *memRegistry) ByFingerprint(fpr string) (Node, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.nodes {
		if n.Fingerprint == fpr {
			return n, true
		}
	}
	return Node{}, false
}

func (r *memRegistry) All() []Node {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, n)
	}
	return out
}

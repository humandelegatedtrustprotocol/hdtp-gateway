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
	ModePassthrough Mode = "passthrough"
	ModeTerminate   Mode = "terminate"
)

// Node is one paired node: its identity pin, its subdomain, its mode, and the
// per-node data-plane secret minted at pairing.
type Node struct {
	Fingerprint string    `json:"fingerprint"`
	SPKI        []byte    `json:"spki"`
	Subdomain   string    `json:"subdomain"`
	Mode        Mode      `json:"mode"`
	Secret      string    `json:"secret"` // data-plane login credential (frp metadata)
	PairedAt    time.Time `json:"paired_at"`
}

// Registry is the ingress's book of paired nodes and outstanding pairing
// tokens. In-memory here; the interface is the persistence seam.
type Registry interface {
	MintToken(ttl time.Duration) (string, error)
	// ConsumeToken burns a token: exactly one pairing per token.
	ConsumeToken(token string) bool
	Put(n Node) error
	BySubdomain(sub string) (Node, bool)
	ByFingerprint(fpr string) (Node, bool)
	All() []Node
}

type memRegistry struct {
	mu     sync.Mutex
	tokens map[string]time.Time
	nodes  map[string]Node // by subdomain
	now    func() time.Time
}

// NewMemoryRegistry returns an in-memory Registry (now is a clock seam).
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

// ValidSubdomain accepts one DNS label: lowercase letters, digits, hyphens.
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

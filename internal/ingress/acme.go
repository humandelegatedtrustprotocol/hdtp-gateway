package ingress

// ACME for terminate-mode subdomains (SPEC §10.6): certmagic — issuance,
// storage, renewal, per-SNI serving — with HTTP-01 for single names and DNS-01
// (libdns provider) for wildcards. Off-the-shelf on purpose; this file only
// wires it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/caddyserver/certmagic"
)

// ACMEOptions configures the issuer.
type ACMEOptions struct {
	StorageDir string
	CA         string // directory URL; "" = certmagic's default (Let's Encrypt)
	Email      string
	// TrustedRoots for the CA's own HTTPS (test CAs like Pebble); nil = system.
	TrustedRoots *x509.CertPool
	// HTTP01Port: the port the HTTP-01 challenge listens on (80 in production;
	// tests use a free port, which Pebble is told about).
	HTTP01Port int
	ListenHost string
	// DNS is the libdns provider for DNS-01 (needed for wildcards); nil = off.
	DNS         certmagic.DNSProvider
	DNSResolver []string
}

// ACME owns one certmagic config with its OWN cache — never the process-wide
// default, so two ingress instances (or two test CAs) cannot serve each
// other's certificates.
type ACME struct {
	cfg   *certmagic.Config
	cache *certmagic.Cache
}

// NewACME builds the certmagic config and issuer.
func NewACME(o ACMEOptions) (*ACME, error) {
	if o.StorageDir == "" {
		return nil, fmt.Errorf("ingress: acme needs a storage dir")
	}
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
	})
	cfg = certmagic.New(cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: o.StorageDir}})
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:                      o.CA,
		Email:                   o.Email,
		Agreed:                  true,
		TrustedRoots:            o.TrustedRoots,
		DisableTLSALPNChallenge: true, // the public port carries the node's traffic
		AltHTTPPort:             o.HTTP01Port,
		ListenHost:              o.ListenHost,
		CertObtainTimeout:       2 * time.Minute,
	})
	if o.DNS != nil {
		issuer.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: o.DNS, Resolvers: o.DNSResolver,
		}}
	}
	cfg.Issuers = []certmagic.Issuer{issuer}
	return &ACME{cfg: cfg, cache: cache}, nil
}

// Close stops the cache's maintenance goroutine.
func (a *ACME) Close() { a.cache.Stop() }

// Manage obtains (or loads) and keeps renewing certificates for names.
func (a *ACME) Manage(ctx context.Context, names ...string) error {
	return a.cfg.ManageSync(ctx, names)
}

// TLSConfig serves the managed certificates per SNI.
func (a *ACME) TLSConfig() *tls.Config {
	c := a.cfg.TLSConfig()
	c.MinVersion = tls.VersionTLS12
	// certmagic returns NextProtos = ["acme-tls/1"] and nothing else: that config
	// is meant to be MERGED into a server config, not served as one. Used as-is
	// the listener advertises only the ACME challenge protocol, so every client
	// that offers ALPN — browsers, curl, Go's net/http — is refused with
	// no_application_protocol, and SPEC §10.6's "reachable at plain
	// https://name.domain" holds for nothing real.
	//
	// http/1.1 and no h2, deliberately: the terminator splices the decrypted
	// stream into a SEPARATE TLS leg to the node, which negotiates its own ALPN
	// and serves HTTP/1.1. Advertising h2 out front would have the caller write
	// HTTP/2 frames into an HTTP/1.1 server. Server order wins in Go's ALPN
	// negotiation, so http/1.1 goes first.
	c.NextProtos = append([]string{"http/1.1"}, c.NextProtos...)
	return c
}

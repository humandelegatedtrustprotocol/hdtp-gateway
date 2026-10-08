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
	// StorageDir is certmagic's file storage path (certificates and account keys).
	// NewACME refuses an empty one.
	StorageDir string
	CA         string // directory URL; "" = certmagic's default (Let's Encrypt)
	// Email is the ACME account contact. Terms of service are always agreed.
	Email string
	// TrustedRoots for the CA's own HTTPS (test CAs like Pebble); nil = system.
	TrustedRoots *x509.CertPool
	// HTTP01Port: the port the HTTP-01 challenge listens on (80 in production;
	// tests use a free port, which Pebble is told about).
	HTTP01Port int
	// ListenHost is the host (no port) the HTTP-01 challenge listener binds.
	ListenHost string
	// DNS is the libdns provider for DNS-01 (needed for wildcards); nil = off.
	DNS certmagic.DNSProvider
	// DNSResolver lists the resolvers certmagic uses to check DNS-01 propagation;
	// it has effect only when DNS is set.
	DNSResolver []string
}

// ACME owns one certmagic config with its OWN cache — never the process-wide
// default, so two ingress instances (or two test CAs) cannot serve each
// other's certificates.
type ACME struct {
	cfg   *certmagic.Config
	cache *certmagic.Cache
}

// NewACME builds the certmagic config and issuer. The TLS-ALPN challenge is disabled (the
// public port carries the node's traffic), so a single name is proven by HTTP-01 on
// HTTP01Port and a wildcard by DNS-01 when DNS is set. It refuses an empty StorageDir with an
// error and contacts no CA: issuance happens in Manage. The cache is its own, not certmagic's
// process-wide default. Close it when done.
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

// Manage obtains (or loads from storage) a certificate for each name, waiting for issuance
// (certmagic's ManageSync), and keeps renewing them afterwards. It returns certmagic's error
// if a name cannot be obtained.
func (a *ACME) Manage(ctx context.Context, names ...string) error {
	return a.cfg.ManageSync(ctx, names)
}

// TLSConfig returns a server config that serves the managed certificates per SNI, with
// MinVersion TLS 1.2 and ALPN "http/1.1" offered first (no h2; the reason is below).
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

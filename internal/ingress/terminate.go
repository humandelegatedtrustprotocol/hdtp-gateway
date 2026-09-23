package ingress

// Terminate mode (SPEC §10.6): the ingress holds a public ACME certificate for
// the subdomain, terminates the public TLS session, and opens a FRESH,
// mutually-pinned mTLS connection to the node over the data plane — the
// "TLS→mTLS conversion". The onward leg rides the node's reverse tunnel under
// its internal SNI; the node pins the ingress certificate, the ingress pins
// the node's SPKI from pairing, and bytes are piped both ways. The fronted node
// derives edge mode: identity toward callers rests on sealed envelopes.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

// Terminator listens on the public port for terminate-mode subdomains.
type Terminator struct {
	Registry Registry
	Domain   string
	// Public is the ACME-backed server config (certmagic TLSConfig); its
	// GetCertificate answers per SNI.
	Public *tls.Config
	// IngressCert is presented on the onward mTLS leg (the node pins it).
	IngressCert tls.Certificate
	// DataPlaneAddr is where the internal SNI routes (frps vhost port).
	DataPlaneAddr string
	Audit         func(action, resource, outcome string)
	DialTimeout   time.Duration

	mu sync.Mutex
	ln net.Listener
}

func (t *Terminator) audit(action, resource, outcome string) {
	if t.Audit != nil {
		t.Audit(action, resource, outcome)
	}
}

// Serve accepts public TLS connections on ln until it closes.
func (t *Terminator) Serve(ln net.Listener) error {
	t.mu.Lock()
	t.ln = ln
	t.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go t.handle(c)
	}
}

func (t *Terminator) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ln != nil {
		return t.ln.Close()
	}
	return nil
}

// subdomainOf maps an SNI back to the registry's subdomain.
func (t *Terminator) subdomainOf(sni string) (string, bool) {
	return subdomainOf(sni, t.Domain)
}

func (t *Terminator) handle(raw net.Conn) {
	defer raw.Close()
	pub := tls.Server(raw, t.Public)
	if err := pub.Handshake(); err != nil {
		return
	}
	sni := pub.ConnectionState().ServerName
	sub, ok := t.subdomainOf(sni)
	if !ok {
		return
	}
	node, ok := t.Registry.BySubdomain(sub)
	if !ok || node.Mode != ModeTerminate {
		t.audit("ingress_terminate", "sni:"+sni, "unknown")
		return
	}
	onward, err := t.DialNode(context.Background(), node)
	if err != nil {
		t.audit("ingress_terminate", "subdomain:"+sub, "unavailable")
		return
	}
	defer onward.Close()
	t.audit("ingress_terminate", "subdomain:"+sub, "ok")
	pipe(pub, onward)
}

// DialNode opens the onward mutually-pinned mTLS leg to a terminate-mode node
// through the data plane. The served certificate MUST carry the SPKI pinned at
// pairing — an unpinned or substituted node is refused (SPEC §10.6).
func (t *Terminator) DialNode(ctx context.Context, node Node) (*tls.Conn, error) {
	timeout := t.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: timeout}
	rawConn, err := d.DialContext(ctx, "tcp", t.DataPlaneAddr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:         InternalName(node.Subdomain, t.Domain),
		Certificates:       []tls.Certificate{t.IngressCert},
		InsecureSkipVerify: true, // #nosec G402 -- pinned below; chains are irrelevant (PACT §2)
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("ingress: node served no certificate")
			}
			spki, err := x509.MarshalPKIXPublicKey(cs.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}
			if string(spki) != string(node.SPKI) {
				fpr, _ := identity.Fingerprint(cs.PeerCertificates[0].PublicKey)
				return fmt.Errorf("ingress: node key %s is not the one pinned at pairing (%s)", fpr, node.Fingerprint)
			}
			return nil
		},
	}
	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// pipe copies both directions until either side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// PinOnwardLeg is the NODE side of the onward leg: it makes tc require a client
// certificate and accept only the paired ingress's — nothing else may deliver
// traffic to a terminate-mode node (SPEC §10.6). It is a transport check and
// stops at the handshake. refused, when set, hears the fingerprint of any other
// certificate presented. The node's listener calls this (node.TLSConfig), so the
// tests that exercise it exercise the pin that ships.
func PinOnwardLeg(tc *tls.Config, ingressFingerprint string, refused func(presented string)) {
	tc.ClientAuth = tls.RequireAnyClientCert
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("node: this listener only accepts its paired ingress")
		}
		f, err := identity.Fingerprint(cs.PeerCertificates[0].PublicKey)
		if err != nil {
			return err
		}
		if f != ingressFingerprint {
			if refused != nil {
				refused(f)
			}
			return fmt.Errorf("node: %s is not the paired ingress", f)
		}
		return nil
	}
}

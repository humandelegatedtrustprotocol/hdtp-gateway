package outbound

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/tech-sumit/pact-gateway/internal/identity"
	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// identity20 is a 2.0 identity for a test: a root, a leaf naming an endpoint,
// and the leaf's key as the node's keypair with the chain attached.
type identity20 struct {
	root     *pactidentity.PrivateKey
	rootCert []byte
	rootFpr  string
	kp       *identity.Keypair
	leaf     []byte
	endpoint string
}

func newIdentity20(t *testing.T, cn, endpoint string) *identity20 {
	t.Helper()
	root, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: cn, Key: root, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := identity.Generate(identity.AlgoEd25519)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := identity.ToLib(kp)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pactidentity.BuildLeaf(pactidentity.LeafOpts{
		CN: cn, RootCN: cn, RootKey: root, HostPub: lib.Public, Endpoint: endpoint,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(300 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	kp.Leaf, kp.Root = leaf, rootCert
	return &identity20{root: root, rootCert: rootCert, rootFpr: pactidentity.Fingerprint(root.Public.SPKI), kp: kp, leaf: leaf, endpoint: endpoint}
}

func (i *identity20) tlsCert() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{i.leaf, i.rootCert}, PrivateKey: i.kp.Signer}
}

func (i *identity20) client() *Client { return &Client{Keypair: i.kp, Cert: i.tlsCert()} }

// peerOf is the pin a caller holds for this identity.
func (i *identity20) peerOf() Peer {
	return Peer{Endpoint: i.endpoint, Seal: "required", Root: i.rootFpr, Leaf: i.leaf}
}

// TestChainAsServerCertificateValidatesToThePinnedRoot: PACT §2 server side —
// a 2.0 node presents its own chain; a caller validates it to the root it
// pinned at the address it dialed, refuses another root, refuses another
// address, and refuses a pin that names a leaf key rather than a root.
func TestChainAsServerCertificateValidatesToThePinnedRoot(t *testing.T) {
	server := newIdentity20(t, "Bharat", "https://agent.bharat.example/mcp")
	got := make(chan []*x509.Certificate, 8)
	addr := startTLS(t, &tls.Config{Certificates: []tls.Certificate{server.tlsCert()}, ClientAuth: tls.RequestClientCert}, got)

	caller := newIdentity20(t, "Alina", "https://agent.alina.example/mcp").client()
	dial := func(peer Peer) error {
		conn, err := tls.Dial("tcp", addr, caller.tlsConfig(peer, "agent.bharat.example"))
		if err != nil {
			return err
		}
		conn.Close()
		<-got
		return nil
	}
	if err := dial(server.peerOf()); err != nil {
		t.Fatalf("the pinned root's chain must be accepted: %v", err)
	}
	// The chain travels as OUR client certificate too (PACT §2): the server
	// saw two certificates, the leaf first.
	other := newIdentity20(t, "Mallory", "https://agent.bharat.example/mcp")
	wrong := server.peerOf()
	wrong.Root = other.rootFpr
	if err := dial(wrong); err == nil || !strings.Contains(err.Error(), "neither a chain under the pinned root nor a WebPKI-valid certificate") {
		t.Fatalf("a chain to another root must be refused: %v", err)
	}
	elsewhere := server.peerOf()
	elsewhere.Endpoint = "https://agent.bharat.example/other"
	if err := dial(elsewhere); err == nil {
		t.Fatal("a chain naming another address must be refused (PACT §14.2 rule 5)")
	}
	// And the LEAF's key is not the identity. The retired generation recognised a server by the
	// key of the certificate it presented; under 2.0 the identity is the root. So a pin that
	// names the leaf key's fingerprint where the root belongs is a pin of somebody who does not
	// exist: the chain does not validate to it, the chain is not publicly trusted either, and
	// the dial fails. A test here once asserted the opposite, and passed, which is how a rule
	// nobody meant to keep survives its own deletion.
	lib, _ := identity.ToLib(server.kp)
	byLeafKey := server.peerOf()
	byLeafKey.Root = pactidentity.Fingerprint(lib.Public.SPKI)
	if err := dial(byLeafKey); err == nil {
		t.Fatal("a pin of the leaf's key must not connect: the identity is the root (PACT §2)")
	}
	// Nor is no pin at all: with no root held there is no chain to validate to, and what is left
	// is WebPKI, which this chain is not.
	if err := dial(Peer{Endpoint: server.endpoint, Seal: "required"}); err == nil {
		t.Fatal("a peer we hold no root for connected on the strength of a chain nobody checked")
	}
}

func TestClientPresentsItsChain(t *testing.T) {
	got := make(chan []*x509.Certificate, 2)
	// The server presents a real chain, because since 2026-09-18 nothing else is
	// recognised: a self-signed certificate names no root and a caller refuses it
	// whatever fingerprint it is pinned under.
	server := newIdentity20(t, "Bharat", "https://agent.bharat.example/mcp")
	addr := startTLS(t, &tls.Config{Certificates: []tls.Certificate{server.tlsCert()}, ClientAuth: tls.RequestClientCert}, got)
	me := newIdentity20(t, "Alina", "https://agent.alina.example/mcp")
	conn, err := tls.Dial("tcp", addr, me.client().tlsConfig(server.peerOf(), "agent.bharat.example"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	certs := <-got
	if len(certs) != 2 || string(certs[0].Raw) != string(me.leaf) || string(certs[1].Raw) != string(me.rootCert) {
		t.Fatalf("the client must present [leaf, root]: %d certificates", len(certs))
	}
}

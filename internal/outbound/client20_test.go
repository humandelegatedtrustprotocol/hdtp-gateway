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
	kp.Leaf, kp.Root, kp.Protocol = leaf, rootCert, 2
	return &identity20{root: root, rootCert: rootCert, rootFpr: pactidentity.Fingerprint(root.Public.SPKI), kp: kp, leaf: leaf, endpoint: endpoint}
}

func (i *identity20) tlsCert() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{i.leaf, i.rootCert}, PrivateKey: i.kp.Signer}
}

func (i *identity20) client() *Client { return &Client{Keypair: i.kp, Cert: i.tlsCert()} }

// peerOf is the pin a caller holds for this identity.
func (i *identity20) peerOf() Peer {
	return Peer{Endpoint: i.endpoint, Fingerprint: i.rootFpr, Seal: "required", Protocol: 2, Root: i.rootFpr, Leaf: i.leaf}
}

// TestChainAsServerCertificateValidatesToThePinnedRoot: PACT §2 server side,
// option (b) — a 2.0 node presents its own chain; a 2.0 caller validates it to
// the root it pinned at the address it dialed, refuses another root, and a 1.x
// caller still recognises the leaf's key (Appendix C).
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
	wrong.Root, wrong.Fingerprint = other.rootFpr, other.rootFpr
	if err := dial(wrong); err == nil || !strings.Contains(err.Error(), "neither the pinned key nor WebPKI-valid") {
		t.Fatalf("a chain to another root must be refused: %v", err)
	}
	elsewhere := server.peerOf()
	elsewhere.Endpoint = "https://agent.bharat.example/other"
	if err := dial(elsewhere); err == nil {
		t.Fatal("a chain naming another address must be refused (PACT §14.2 rule 5)")
	}
	// A 1.x caller pins the leaf's key and reads PeerCertificates[0].
	lib, _ := identity.ToLib(server.kp)
	if err := dial(Peer{Endpoint: server.endpoint, Fingerprint: pactidentity.Fingerprint(lib.Public.SPKI), Seal: "required"}); err != nil {
		t.Fatalf("a 1.x pin of the leaf's key must still connect: %v", err)
	}
}

func TestClientPresentsItsChain(t *testing.T) {
	got := make(chan []*x509.Certificate, 2)
	srvKP, _ := identity.Generate(identity.AlgoP256)
	srvDER, _ := identity.SelfSignedCert(srvKP, "peer")
	addr := startTLS(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKP.Signer}}, ClientAuth: tls.RequestClientCert}, got)
	me := newIdentity20(t, "Alina", "https://agent.alina.example/mcp")
	conn, err := tls.Dial("tcp", addr, me.client().tlsConfig(Peer{Endpoint: "https://x.example/mcp", Fingerprint: srvKP.Fingerprint}, "x.example"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	certs := <-got
	if len(certs) != 2 || string(certs[0].Raw) != string(me.leaf) || string(certs[1].Raw) != string(me.rootCert) {
		t.Fatalf("the client must present [leaf, root]: %d certificates", len(certs))
	}
}

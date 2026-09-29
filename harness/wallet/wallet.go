// Package wallet plays the PERSON in a harness topology.
//
// A PACT 2.x account is nobody until a wallet has signed it a leaf: the identity is the person's
// root, which no host ever holds, and the host serves under a leaf that root issued for the
// address it answers at (PACT §2, §9). `account create` therefore makes an account that has no
// certificate to present, and a node asked to serve it ends the handshake.
//
// Every scenario here used to create an account and call it, which was the whole ceremony in
// 1.x, where the key the node minted WAS the identity. None of them could run after 1.x went,
// and none of them said so: the live scenarios are skipped unless PACT_HARNESS_LIVE is set, and
// the hook that runs this module does not set it.
//
// So the harness holds a root per person and does what an owner does with the `pact` CLI:
//
//	account csr -slug S            the node mints a key and asks for a leaf
//	(the wallet issues)            IssueFromCSR, under the person's root
//	account install-leaf -chain F  the node installs [leaf, root] and starts serving
//
// and hands back what a caller pins: the root's fingerprint, the leaf, and the address in it.
package wallet

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pactidentity "github.com/pact-cloud/pact-identity/go"
)

// Wallet is one person's root.
type Wallet struct {
	CN      string
	Key     *pactidentity.PrivateKey
	RootDER []byte
	// Fingerprint is the identity: what a contact pins (PACT §2).
	Fingerprint string
}

// New mints a root for a person.
func New(cn string) (*Wallet, error) {
	key, err := pactidentity.GenerateKey("ed25519")
	if err != nil {
		return nil, fmt.Errorf("wallet: minting %s's root key: %w", cn, err)
	}
	root, err := pactidentity.BuildRoot(pactidentity.RootOpts{CN: cn, Key: key, NotBefore: time.Now().Add(-24 * time.Hour)})
	if err != nil {
		return nil, fmt.Errorf("wallet: minting %s's root certificate: %w", cn, err)
	}
	return &Wallet{CN: cn, Key: key, RootDER: root, Fingerprint: pactidentity.Fingerprint(key.Public().SPKI)}, nil
}

// Pin is what a caller holds of a certified account: enough to dial it, recognise it, and seal
// to it, and nothing a caller could not have read off its card.
type Pin struct {
	Root     string // the person's root fingerprint
	Leaf     []byte // the leaf this host serves under, DER
	Endpoint string // the address that leaf names
}

// Node is how the wallet reaches the node it is certifying. The image is distroless — no shell
// to redirect into — so a file arrives by being copied in.
type Node interface {
	// Exec runs `/pact-gateway <args>` inside the node and returns what it printed.
	Exec(ctx context.Context, args ...string) ([]byte, error)
	// CopyIn puts a host file at a path inside the node.
	CopyIn(ctx context.Context, hostPath, nodePath string) error
}

// Certify gives the account a leaf under this root and returns the pin. `purpose` is "" for the
// node's own default (signup before the first leaf, renew after) or "move"; `endpoint` is "" for
// the node's public URL.
func (w *Wallet) Certify(ctx context.Context, n Node, slug, purpose, endpoint string) (Pin, error) {
	return w.certify(ctx, n, slug, purpose, endpoint, time.Time{})
}

// CertifyUntil is Certify with a leaf that expires at notAfter — within a day of now — as a
// person may choose a short life for one (a leaf's lifetime is the person's choice). A scenario
// uses it to watch a leaf expire: what a host does with the key of a leaf past its notAfter
// (PACT §14.4) cannot be seen otherwise without moving a clock.
func (w *Wallet) CertifyUntil(ctx context.Context, n Node, slug, purpose, endpoint string, notAfter time.Time) (Pin, error) {
	return w.certify(ctx, n, slug, purpose, endpoint, notAfter)
}

func (w *Wallet) certify(ctx context.Context, n Node, slug, purpose, endpoint string, notAfter time.Time) (Pin, error) {
	args := []string{"account", "csr", "-slug", slug}
	if purpose != "" {
		args = append(args, "-purpose", purpose)
	}
	if endpoint != "" {
		args = append(args, "-endpoint", endpoint)
	}
	out, err := n.Exec(ctx, args...)
	if err != nil {
		return Pin{}, fmt.Errorf("wallet: account csr for %s: %w (%s)", slug, err, bytes.TrimSpace(out))
	}
	// The request is the PEM block; the line above it is for a person.
	block, _ := pem.Decode(out[max(0, bytes.Index(out, []byte("-----BEGIN"))):])
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return Pin{}, fmt.Errorf("wallet: account csr for %s printed no certificate request: %s", slug, bytes.TrimSpace(out))
	}
	var previous *time.Time
	if purpose != "" && purpose != "signup" {
		// A successor leaf must be newer than the one it supersedes (PACT §14.3); a wallet that
		// issues with its own clock alone can tie with a leaf it issued a moment ago.
		t := time.Now().Add(-time.Hour)
		previous = &t
	}
	now, days := time.Now(), 365
	if !notAfter.IsZero() {
		// One day's validity, ending at notAfter. The core starts a leaf an hour before the
		// wallet's clock and ends it a day after that start (pactidentity issuePlan), so the clock
		// is set 23 hours before notAfter.
		now, days = notAfter.Add(-23*time.Hour), 1
	}
	issued, err := pactidentity.IssueFromCSR(block.Bytes, pactidentity.IssueOpts{
		RootCN: w.CN, RootKey: w.Key, RootSPKIs: [][]byte{w.Key.Public().SPKI},
		Now: now, PreviousNotBefore: previous, ValidDays: days,
	})
	if err != nil {
		return Pin{}, fmt.Errorf("wallet: issuing %s's leaf: %w", slug, err)
	}
	dir, err := os.MkdirTemp("", "pact-harness-wallet-")
	if err != nil {
		return Pin{}, err
	}
	defer os.RemoveAll(dir)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.DER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.RootDER})...)
	host := filepath.Join(dir, "chain.pem")
	// 0644: `docker cp` keeps the mode, and the node runs as nonroot.
	if err := os.WriteFile(host, chain, 0o644); err != nil { //nolint:gosec // two public certificates
		return Pin{}, err
	}
	const inNode = "/tmp/harness-chain.pem"
	if err := n.CopyIn(ctx, host, inNode); err != nil {
		return Pin{}, fmt.Errorf("wallet: handing %s its chain: %w", slug, err)
	}
	if out, err := n.Exec(ctx, "account", "install-leaf", "-slug", slug, "-chain", inNode); err != nil {
		return Pin{}, fmt.Errorf("wallet: account install-leaf for %s: %w (%s)", slug, err, bytes.TrimSpace(out))
	}
	return Pin{Root: w.Fingerprint, Leaf: issued.DER, Endpoint: issued.Endpoint}, nil
}

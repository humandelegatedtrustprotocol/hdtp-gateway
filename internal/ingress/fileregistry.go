package ingress

// Persisting the book of paired nodes (SPEC §10.6).
//
// The ingress kept its registry in memory, so every pairing died with the
// process: after a restart — or a deploy, or a crash — every node that had
// paired became unknown, its subdomain routed nowhere, and the owner had to
// re-pair each one by hand. `Registry` was always described as the persistence
// seam; nothing had implemented it.
//
// Pairing TOKENS deliberately stay in memory. A token is short-lived and
// single-use, and one that outlives the process is a credential lying on disk
// for no benefit: losing an outstanding token costs one `ingress token` command,
// while persisting it widens the window in which a stolen file can claim a
// subdomain.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type fileRegistry struct {
	*memRegistry // tokens and lookups come from the in-memory implementation

	mu   sync.Mutex // serialises Put, so the book written is the book put
	path string
}

// NewFileRegistry returns a Registry whose pairings survive a restart: it loads the JSON book at
// path (a missing file is a first run, not an error) and puts each row into an in-memory
// registry, so a row that fails Put's checks, or a file that does not parse, is an error naming
// the path. Tokens stay in memory and are never written. Put and Remove persist; MintToken,
// ConsumeToken and the lookups are the in-memory registry's. The file is written 0600, through a temporary
// file renamed over it, after Put's checks have passed and before the in-memory book changes.
func NewFileRegistry(path string, now func() time.Time) (Registry, error) {
	// The file registry checks and writes before the in-memory book changes, so it holds the memory
	// registry itself, not the interface.
	r := &fileRegistry{memRegistry: NewMemoryRegistry(now).(*memRegistry), path: path}
	nodes, err := readNodes(path)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if err := r.memRegistry.Put(n); err != nil {
			return nil, fmt.Errorf("ingress: restoring pairing %s: %w", n.Subdomain, err)
		}
	}
	return r, nil
}

// Put checks the pairing as the in-memory registry does, writes the book with it to disk, and only
// then puts it in memory. A pairing that is not on disk is one the owner will have to repeat, so
// the write happens before the caller is told it worked; and a write that failed leaves the book
// in memory as it was, so the ingress never routes a pairing its next start will not know.
func (r *fileRegistry) Put(n Node) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.memRegistry.mu.Lock()
	err := r.refusal(n)
	book := r.with(n)
	r.memRegistry.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeNodes(r.path, book); err != nil {
		return err
	}
	return r.memRegistry.Put(n)
}

// Remove writes the book without the subdomain's pairing to disk, and only then forgets it in
// memory, for the reason Put writes first.
func (r *fileRegistry) Remove(sub string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.memRegistry.mu.Lock()
	book, held := r.without(sub)
	r.memRegistry.mu.Unlock()
	if !held {
		return ErrNotPaired
	}
	if err := writeNodes(r.path, book); err != nil {
		return err
	}
	return r.memRegistry.Remove(sub)
}

func readNodes(path string) ([]Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // a first run has no book yet
		}
		return nil, fmt.Errorf("ingress: reading %s: %w", path, err)
	}
	var nodes []Node
	if err := json.Unmarshal(b, &nodes); err != nil {
		return nil, fmt.Errorf("ingress: %s is unreadable: %w", path, err)
	}
	return nodes, nil
}

// writeNodes replaces the file atomically: a half-written book would lose
// pairings that were already made, which is the failure this file exists to
// prevent. The secret each row carries is a data-plane credential, so the file
// is 0600 and so is the temporary one it is renamed from.
func writeNodes(path string, nodes []Node) error {
	b, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ingress-nodes-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

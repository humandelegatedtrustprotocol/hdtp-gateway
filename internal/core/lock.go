package core

// Store lock (SPEC §12.1): `serve` holds it for the node's lifetime; offline commands
// that touch the database directly (migrate) MUST acquire it first and therefore
// refuse to run while the node does. flock-based: released automatically if the
// process dies, so a crash never wedges the data dir.

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type Lock struct {
	f *os.File
}

// AcquireLock takes the exclusive data-dir lock, failing immediately (no blocking)
// if another process holds it.
func AcquireLock(dataDir string) (*Lock, error) {
	path := filepath.Join(dataDir, "pact.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock: data dir %s is in use by another pact-gateway process", dataDir)
	}
	return &Lock{f: f}, nil
}

func (l *Lock) Release() error {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	return l.f.Close()
}

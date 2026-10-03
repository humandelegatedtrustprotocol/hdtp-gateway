package core

// The data-dir lock (SPEC §12.1). It has two strengths.
//
//   - Exclusive: an offline command that must be alone with the data dir — `migrate`, `export` and
//     `import`, the `audit` commands — takes it and refuses to run while any `serve` holds the dir;
//     `doctor` tries it to learn whether a node is running.
//   - Shared: `serve`. Several `serve` processes may share one data dir on ONE host (SPEC §11.1:
//     SQLite in WAL mode serves many processes on one host, never across hosts), and each holds the
//     lock shared for its lifetime. The first to start takes it exclusively, migrates the store
//     while it is alone, and only then shares it (AcquireServeLock, Lock.Share).
//
// flock-based: released automatically if the process dies, so a crash never wedges the data dir.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Lock struct {
	f         *os.File
	exclusive bool
}

func openLockFile(dataDir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dataDir, "hdtp.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	return f, nil
}

// AcquireLock takes the exclusive data-dir lock, failing immediately (no blocking)
// if another process holds it, shared or exclusive.
func AcquireLock(dataDir string) (*Lock, error) {
	f, err := openLockFile(dataDir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock: data dir %s is in use by another hdtp-gateway process", dataDir)
	}
	return &Lock{f: f, exclusive: true}, nil
}

// ServeLockWait is how long a `serve` waits for the lock to become shareable: another `serve` that
// is migrating holds it exclusively for as long as the migration takes.
const ServeLockWait = time.Minute

// AcquireServeLock takes the lock for `serve`: exclusively when no other process holds it — the
// caller is then alone, migrates, and calls Share — and otherwise shared, beside the `serve`
// processes already running. It waits up to ServeLockWait while another process holds it
// exclusively, and then refuses: an offline command, or a `serve` still migrating.
func AcquireServeLock(dataDir string) (*Lock, error) {
	f, err := openLockFile(dataDir)
	if err != nil {
		return nil, err
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		return &Lock{f: f, exclusive: true}, nil
	}
	deadline := time.Now().Add(ServeLockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("lock: data dir %s is held alone by another hdtp-gateway process (an offline command, or a serve migrating) and was not released in %s", dataDir, ServeLockWait)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Exclusive reports whether this process holds the lock alone.
func (l *Lock) Exclusive() bool { return l.exclusive }

// Share turns an exclusive lock into a shared one, so other `serve` processes can start beside
// this one. flock converts by releasing and re-taking, so another process can take the lock in
// between; if it takes it exclusively, Share fails, and the caller must stop.
func (l *Lock) Share() error {
	if !l.exclusive {
		return nil
	}
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("lock: sharing the data-dir lock: another process took it alone: %w", err)
	}
	l.exclusive = false
	return nil
}

func (l *Lock) Release() error {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	return l.f.Close()
}

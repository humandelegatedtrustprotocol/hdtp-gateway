package core

// Keyring: the node's master key and the ONLY write path for secrets at rest
// (SPEC §3.7, §11.3). Master key sourcing chain: HDTP_MASTER_KEY env var (base64,
// 32 bytes) > 0600 key file, generated on first run. (SPEC §12.2 also permits an OS
// keyring where one exists; distroless containers have none, and v1 ships env+file —
// the chain leaves room for that source without an interface change.)
//
// Values are sealed with AES-256-GCM; the caller-supplied AAD binds a ciphertext to
// its column/context so a value copied between columns fails to open.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

const masterKeyEnv = "HDTP_MASTER_KEY"

// Keyring seals and opens secret values under the node's master key with AES-256-GCM. It is the
// only write path for secrets at rest (SPEC §3.7). Build one with OpenKeyring.
type Keyring struct {
	aead cipher.AEAD
}

// OpenKeyring resolves the master key (env > file; the file is created 0600 on first
// run) and returns a ready keyring. lookup is injectable for tests; production passes
// os.LookupEnv.
func OpenKeyring(path string, lookup func(string) (string, bool)) (*Keyring, error) {
	var key []byte
	if v, ok := lookup(masterKeyEnv); ok {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("keyring: %s is not base64: %w", masterKeyEnv, err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("keyring: %s must decode to 32 bytes, got %d", masterKeyEnv, len(k))
		}
		key = k
	} else {
		k, err := loadOrCreateKeyFile(path)
		if err != nil {
			return nil, err
		}
		key = k
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return &Keyring{aead: aead}, nil
}

func loadOrCreateKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	switch {
	case err == nil:
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("keyring: %s mode %o is group/world accessible; require 0600", path, fi.Mode().Perm())
		}
		k, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("keyring: %w", err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("keyring: %s holds %d bytes, want 32", path, len(k))
		}
		return k, nil
	case os.IsNotExist(err):
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("keyring: %w", err)
		}
		if err := os.WriteFile(path, k, 0o600); err != nil {
			return nil, fmt.Errorf("keyring: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("keyring: %w", err)
	}
}

// Encrypt seals plaintext under the master key, bound to aad. Output layout:
// nonce ‖ ciphertext (GCM tag included).
func (k *Keyring) Encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return append(nonce, k.aead.Seal(nil, nonce, plaintext, aad)...), nil
}

// Decrypt opens a value produced by Encrypt with the same aad.
func (k *Keyring) Decrypt(sealed, aad []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(sealed) < ns+k.aead.Overhead() {
		return nil, errors.New("keyring: sealed value too short")
	}
	pt, err := k.aead.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, fmt.Errorf("keyring: decrypt failed: %w", err)
	}
	return pt, nil
}

package identity

// Identity backup (SPEC §3.10): one account's keypair, portable to another node.
//
// The whole point is that the file survives the node that made it, so it cannot
// be sealed under that node's keyring — it is sealed under a passphrase the
// owner supplies. That is what makes it a backup, and it is also what makes it
// the most dangerous artifact this product can emit: a plaintext identity is one
// correct guess away. Hence Argon2id rather than a bare hash, and hence §3.10's
// rule that this is reachable only over host shell access.
//
// The cleartext metadata is the AEAD's additional data, so a file whose slug or
// fingerprint has been edited fails to open rather than restoring an identity
// under a name it does not own.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	pactidentity "github.com/tech-sumit/pact-gateway/pact-identity"
)

// BackupVersion is the format version, first in the file so a future reader can
// refuse politely instead of misparsing. Version 1 carries a 1.x identity key;
// version 2 (PACT 2.0) carries a LEAF key with its leaf and the root that
// issued it (PACT §9: a host holds the leaf and its key, never the root).
const (
	BackupVersion   = 1
	BackupVersion20 = 2
)

// Argon2id parameters. Deliberately costly: this file is offline and long-lived,
// so the attacker's budget is unbounded while the owner's wait is once per
// export and once per restore.
const (
	argonTime    = 3
	argonMemory  = 256 * 1024 // 256 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// IdentityBackup is the file. Everything except Ciphertext is cleartext, and all
// of it is bound into the AEAD as additional data.
type IdentityBackup struct {
	Version     int    `json:"pact_identity_backup"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Algo        string `json:"algo"`
	Fingerprint string `json:"fingerprint"`
	KDF         string `json:"kdf"`  // "argon2id"
	AEAD        string `json:"aead"` // "aes-256-gcm"
	Time        uint32 `json:"kdf_time"`
	Memory      uint32 `json:"kdf_memory_kib"`
	Threads     uint8  `json:"kdf_threads"`
	Salt        string `json:"salt"`       // base64
	Nonce       string `json:"nonce"`      // base64
	Ciphertext  string `json:"ciphertext"` // base64: PKCS#8 DER, sealed
	// PACT 2.0 (version 2): the leaf the sealed key belongs to, the root that
	// issued it, and the endpoint the leaf names — all bound as additional
	// data, so a leaf swapped in fails to open. RootFingerprint is the
	// identity; Fingerprint above is the leaf key's.
	Leaf            string `json:"leaf,omitempty"` // base64url DER
	Root            string `json:"root,omitempty"` // base64url DER, the certificate — never a key
	RootFingerprint string `json:"root_fingerprint,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
}

// ErrRootKey is a backup whose sealed key is the ROOT's: a wallet's secret,
// which no host may hold (PACT §9), refused whatever the file claims.
var ErrRootKey = errors.New("identity: the backup holds a root key, which a host never holds")

// ErrPassphrase is returned when a backup does not open under the passphrase
// given — which is also what a tampered file looks like, deliberately: the
// difference between "wrong passphrase" and "edited file" is not something to
// hand an attacker.
var ErrPassphrase = errors.New("identity: wrong passphrase, or the backup has been altered")

// aad is the additional data: every cleartext field, in a fixed order. It binds
// the ciphertext to the identity the file claims to carry.
func (b IdentityBackup) aad() []byte {
	base := fmt.Sprintf("pact-identity-backup/v%d\n%s\n%s\n%s\n%s",
		b.Version, b.Slug, b.DisplayName, b.Algo, b.Fingerprint)
	if b.Version >= BackupVersion20 {
		base += "\n" + b.Leaf + "\n" + b.Root + "\n" + b.RootFingerprint + "\n" + b.Endpoint
	}
	return []byte(base)
}

// ExportIdentity20 seals a 2.0 account's LEAF key with its leaf and root: the
// host's half of the identity, portable to another host that will serve the
// same leaf until the wallet renews it there (PACT §9). The root travels as a
// certificate only; a root key in this file is what OpenIdentity refuses.
func ExportIdentity20(kp *Keypair, slug, displayName, algo, passphrase string, leaf, root []byte) (IdentityBackup, error) {
	parsed, err := pactidentity.Parse(leaf)
	if err != nil {
		return IdentityBackup{}, fmt.Errorf("identity: leaf: %w", err)
	}
	if len(parsed.URIs) != 1 {
		return IdentityBackup{}, errors.New("identity: the leaf names no endpoint")
	}
	rootCert, err := pactidentity.Parse(root)
	if err != nil {
		return IdentityBackup{}, fmt.Errorf("identity: root: %w", err)
	}
	b, err := exportWith(kp, slug, displayName, algo, passphrase, func(b *IdentityBackup) {
		b.Version = BackupVersion20
		b.Leaf, b.Root = base64.RawURLEncoding.EncodeToString(leaf), base64.RawURLEncoding.EncodeToString(root)
		b.RootFingerprint, b.Endpoint = pactidentity.FingerprintOf(rootCert), parsed.URIs[0]
	})
	return b, err
}

func deriveKey(passphrase string, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey([]byte(passphrase), salt, t, m, p, argonKeyLen)
}

// ExportIdentity seals a keypair into a backup document.
func ExportIdentity(kp *Keypair, slug, displayName, algo, passphrase string) (IdentityBackup, error) {
	return exportWith(kp, slug, displayName, algo, passphrase, nil)
}

func exportWith(kp *Keypair, slug, displayName, algo, passphrase string, shape func(*IdentityBackup)) (IdentityBackup, error) {
	if passphrase == "" {
		return IdentityBackup{}, errors.New("identity: a backup needs a passphrase")
	}
	der, err := MarshalPKCS8(kp)
	if err != nil {
		return IdentityBackup{}, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return IdentityBackup{}, err
	}
	b := IdentityBackup{
		Version: BackupVersion, Slug: slug, DisplayName: displayName,
		Algo: algo, Fingerprint: kp.Fingerprint,
		KDF: "argon2id", AEAD: "aes-256-gcm",
		Time: argonTime, Memory: argonMemory, Threads: argonThreads,
		Salt: base64.StdEncoding.EncodeToString(salt),
	}
	if shape != nil {
		shape(&b)
	}
	gcm, err := aeadFor(deriveKey(passphrase, salt, argonTime, argonMemory, argonThreads))
	if err != nil {
		return IdentityBackup{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return IdentityBackup{}, err
	}
	b.Nonce = base64.StdEncoding.EncodeToString(nonce)
	b.Ciphertext = base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, der, b.aad()))
	return b, nil
}

// OpenIdentity recovers the keypair from a backup document.
func OpenIdentity(b IdentityBackup, passphrase string) (*Keypair, error) {
	if b.Version != BackupVersion && b.Version != BackupVersion20 {
		return nil, fmt.Errorf("identity: backup version %d, this build understands %d and %d", b.Version, BackupVersion, BackupVersion20)
	}
	if b.KDF != "argon2id" || b.AEAD != "aes-256-gcm" {
		return nil, fmt.Errorf("identity: unsupported kdf %q / aead %q", b.KDF, b.AEAD)
	}
	salt, err := base64.StdEncoding.DecodeString(b.Salt)
	if err != nil {
		return nil, fmt.Errorf("identity: salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(b.Nonce)
	if err != nil {
		return nil, fmt.Errorf("identity: nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(b.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("identity: ciphertext: %w", err)
	}
	// The file's OWN parameters, not this build's constants: a backup taken
	// before a cost change must still open.
	gcm, err := aeadFor(deriveKey(passphrase, salt, b.Time, b.Memory, b.Threads))
	if err != nil {
		return nil, err
	}
	der, err := gcm.Open(nil, nonce, ct, b.aad())
	if err != nil {
		return nil, ErrPassphrase
	}
	kp, err := ParsePKCS8(der)
	if err != nil {
		return nil, fmt.Errorf("identity: the backup did not hold a usable key: %w", err)
	}
	// The cleartext fingerprint is a claim until the key proves it. A mismatch
	// means the file is inconsistent with itself; refuse rather than import an
	// identity under the wrong name.
	if kp.Fingerprint != b.Fingerprint {
		return nil, fmt.Errorf("identity: the backup's key is %s but the file claims %s",
			kp.Fingerprint, b.Fingerprint)
	}
	if b.Version >= BackupVersion20 {
		leaf, err := pactidentity.Parse(pactidentity.FromB64url(b.Leaf))
		if err != nil {
			return nil, fmt.Errorf("identity: the backup's leaf does not parse: %w", err)
		}
		if pactidentity.Fingerprint(leaf.SPKI) != kp.Fingerprint {
			return nil, errors.New("identity: the backup's key is not the leaf's")
		}
		root, err := pactidentity.Parse(pactidentity.FromB64url(b.Root))
		if err != nil {
			return nil, fmt.Errorf("identity: the backup's root does not parse: %w", err)
		}
		if pactidentity.Fingerprint(root.SPKI) == kp.Fingerprint {
			return nil, ErrRootKey
		}
		kp.Leaf, kp.Root, kp.Protocol = leaf.DER, root.DER, 2
	}
	return kp, nil
}

func aeadFor(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// MarshalBackup renders a backup as the file's bytes.
func MarshalBackup(b IdentityBackup) ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

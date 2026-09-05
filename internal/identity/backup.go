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
)

// BackupVersion is the format version, first in the file so a future reader can
// refuse politely instead of misparsing.
const BackupVersion = 1

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
}

// ErrPassphrase is returned when a backup does not open under the passphrase
// given — which is also what a tampered file looks like, deliberately: the
// difference between "wrong passphrase" and "edited file" is not something to
// hand an attacker.
var ErrPassphrase = errors.New("identity: wrong passphrase, or the backup has been altered")

// aad is the additional data: every cleartext field, in a fixed order. It binds
// the ciphertext to the identity the file claims to carry.
func (b IdentityBackup) aad() []byte {
	return []byte(fmt.Sprintf("pact-identity-backup/v%d\n%s\n%s\n%s\n%s",
		b.Version, b.Slug, b.DisplayName, b.Algo, b.Fingerprint))
}

func deriveKey(passphrase string, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey([]byte(passphrase), salt, t, m, p, argonKeyLen)
}

// ExportIdentity seals a keypair into a backup document.
func ExportIdentity(kp *Keypair, slug, displayName, algo, passphrase string) (IdentityBackup, error) {
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
	if b.Version != BackupVersion {
		return nil, fmt.Errorf("identity: backup version %d, this build understands %d", b.Version, BackupVersion)
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

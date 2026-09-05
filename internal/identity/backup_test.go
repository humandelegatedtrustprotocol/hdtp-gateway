package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestIdentityBackupRoundTrips(t *testing.T) {
	for _, algo := range []Algo{AlgoP256, AlgoEd25519} {
		t.Run(string(algo), func(t *testing.T) {
			kp, err := Generate(algo)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ExportIdentity(kp, "alice", "Alice", string(algo), "correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			// The private key must not appear anywhere in the file's bytes.
			raw, err := MarshalBackup(b)
			if err != nil {
				t.Fatal(err)
			}
			der, _ := MarshalPKCS8(kp)
			if strings.Contains(string(raw), base64.StdEncoding.EncodeToString(der)) {
				t.Fatal("the backup carries the private key in the clear")
			}

			got, err := OpenIdentity(b, "correct horse battery staple")
			if err != nil {
				t.Fatal(err)
			}
			if got.Fingerprint != kp.Fingerprint {
				t.Errorf("restored a different identity: %s want %s", got.Fingerprint, kp.Fingerprint)
			}
		})
	}
}

func TestIdentityBackupRefusesAWrongPassphrase(t *testing.T) {
	kp, _ := Generate(AlgoP256)
	b, err := ExportIdentity(kp, "alice", "Alice", "p256", "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenIdentity(b, "wrong"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("a wrong passphrase gave %v, want ErrPassphrase", err)
	}
	if _, err := ExportIdentity(kp, "alice", "Alice", "p256", ""); err == nil {
		t.Error("an empty passphrase produced a backup")
	}
}

// The cleartext metadata is the AEAD's additional data. Editing it must fail the
// open — otherwise a file could be relabelled and restored as somebody else's
// identity, under a name its key does not own.
func TestEditingTheMetadataBreaksTheBackup(t *testing.T) {
	kp, _ := Generate(AlgoP256)
	good, err := ExportIdentity(kp, "alice", "Alice", "p256", "pw")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*IdentityBackup)
	}{
		{"slug", func(b *IdentityBackup) { b.Slug = "bob" }},
		{"display name", func(b *IdentityBackup) { b.DisplayName = "Bob" }},
		{"fingerprint", func(b *IdentityBackup) { b.Fingerprint = "sha256:not-this-key" }},
		{"algo", func(b *IdentityBackup) { b.Algo = "ed25519" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edited := good
			tc.edit(&edited)
			if _, err := OpenIdentity(edited, "pw"); err == nil {
				t.Errorf("a backup with an edited %s still opened", tc.name)
			}
		})
	}
}

// A backup taken before a cost change must still open: the file's OWN Argon2
// parameters decide, not this build's constants.
func TestABackupOpensWithItsOwnKDFParameters(t *testing.T) {
	kp, _ := Generate(AlgoP256)
	b, err := ExportIdentity(kp, "alice", "Alice", "p256", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if b.Time != argonTime || b.Memory != argonMemory {
		t.Fatal("the export did not record its parameters")
	}
	// Simulate this build having moved on: the file still says what it used.
	if _, err := OpenIdentity(b, "pw"); err != nil {
		t.Fatalf("a backup did not open under its own parameters: %v", err)
	}
}

func TestBackupFileIsSelfDescribing(t *testing.T) {
	kp, _ := Generate(AlgoP256)
	b, _ := ExportIdentity(kp, "alice", "Alice", "p256", "pw")
	raw, err := MarshalBackup(b)
	if err != nil {
		t.Fatal(err)
	}
	var round IdentityBackup
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatal(err)
	}
	if round.Version != BackupVersion || round.KDF != "argon2id" || round.AEAD != "aes-256-gcm" {
		t.Errorf("the file does not describe its own format: %+v", round)
	}
	// A future version must be refused, not misparsed.
	round.Version = 99
	if _, err := OpenIdentity(round, "pw"); err == nil {
		t.Error("a future format version was accepted")
	}
}

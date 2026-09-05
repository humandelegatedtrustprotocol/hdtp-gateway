package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

func loadVectors(t *testing.T) []Vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []Vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) != 4 {
		t.Fatalf("want 4 vectors, got %d", len(vs))
	}
	return vs
}

// TestVectorsOpenAndVerify: every committed vector decrypts to the recorded
// plaintext and its signature verifies — the interop contract (PACT §13.5).
func TestVectorsOpenAndVerify(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			dec := func(s string) []byte {
				b, err := base64.RawURLEncoding.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			env := &Envelope{Protected: dec(v.Protected), Enc: dec(v.Enc), CT: dec(v.CT), Sig: dec(v.Sig)}

			rDER, _ := hex.DecodeString(v.RecipKeyHex)
			recip, err := identity.ParsePKCS8(rDER)
			if err != nil {
				t.Fatal(err)
			}
			sDER, _ := hex.DecodeString(v.SenderKeyHex)
			sender, err := identity.ParsePKCS8(sDER)
			if err != nil {
				t.Fatal(err)
			}

			if err := VerifySig(env, sender.Signer.Public()); err != nil {
				t.Fatalf("signature: %v", err)
			}
			pt, err := Open(recip, env)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			want, _ := hex.DecodeString(v.PlaintextHex)
			if !bytes.Equal(pt, want) {
				t.Fatal("plaintext mismatch")
			}
			h, err := ParseHeader(env)
			if err != nil || h.Suite != v.Suite || h.From != sender.Fingerprint || h.To != recip.Fingerprint {
				t.Fatalf("header: %v %+v", err, h)
			}
		})
	}
}

// TestVectorsDeterministic: regeneration reproduces the committed file — byte for
// byte, EXCEPT the sig of ECDSA senders: Go's ecdsa.SignASN1 is deliberately
// nondeterministic (randutil.MaybeReadByte), so the committed ECDSA sig is one
// valid signature (proven by TestVectorsOpenAndVerify) while keys, header,
// plaintext, enc, and ct are exactly reproducible; Ed25519 sigs compare exactly.
func TestVectorsDeterministic(t *testing.T) {
	vs, err := GenerateVectors()
	if err != nil {
		t.Fatal(err)
	}
	committed := loadVectors(t)
	for i := range vs {
		got, want := vs[i], committed[i]
		ecdsaSender := strings.HasPrefix(got.Name, "p256-to-")
		if ecdsaSender {
			got.Sig, want.Sig = "", ""
		}
		if got != want {
			t.Fatalf("vector %s drifted from committed file — envelope behavior changed; regenerate deliberately with genvectors", vs[i].Name)
		}
	}
}

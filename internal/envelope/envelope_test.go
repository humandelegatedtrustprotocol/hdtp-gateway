package envelope

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/tech-sumit/pact-gateway/internal/identity"
)

func kp(t *testing.T, algo identity.Algo) *identity.Keypair {
	t.Helper()
	k, err := identity.Generate(algo)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, sender, recipient *identity.Keypair, pt []byte) *Envelope {
	t.Helper()
	env, err := Seal(SealParams{
		Sender: sender, RecipientPub: recipient.Signer.Public(), To: recipient.Fingerprint,
		MsgID: "m-1", TS: 1756000000, Exp: 1756000600, CTY: CTYCall,
	}, pt)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestRoundTripAllPairs(t *testing.T) {
	algos := []identity.Algo{identity.AlgoP256, identity.AlgoEd25519}
	for _, sa := range algos {
		for _, ra := range algos {
			t.Run(string(sa)+"->"+string(ra), func(t *testing.T) {
				sender, recipient := kp(t, sa), kp(t, ra)
				pt := []byte(`{"method":"tools/list","params":{}}`)
				env := seal(t, sender, recipient, pt)

				hdr, err := ParseHeader(env)
				if err != nil {
					t.Fatal(err)
				}
				if hdr.From != sender.Fingerprint || hdr.To != recipient.Fingerprint || hdr.V != 1 {
					t.Fatalf("header wrong: %+v", hdr)
				}
				wantSuite := SuiteP256
				if ra == identity.AlgoEd25519 {
					wantSuite = SuiteX25519
				}
				if hdr.Suite != wantSuite {
					t.Fatalf("suite %s, want %s", hdr.Suite, wantSuite)
				}
				if err := VerifySig(env, sender.Signer.Public()); err != nil {
					t.Fatalf("sig: %v", err)
				}
				got, err := Open(recipient, env)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatalf("plaintext mismatch")
				}
			})
		}
	}
}

func TestAADTamperFails(t *testing.T) {
	sender, recipient := kp(t, identity.AlgoP256), kp(t, identity.AlgoP256)
	env := seal(t, sender, recipient, []byte("x"))
	// flip a byte in protected — AEAD must refuse
	env.Protected[10] ^= 1
	if _, err := Open(recipient, env); err == nil {
		t.Fatal("tampered AAD opened")
	}
}

func TestSigTamperFails(t *testing.T) {
	sender, recipient := kp(t, identity.AlgoEd25519), kp(t, identity.AlgoP256)
	env := seal(t, sender, recipient, []byte("x"))
	env.Sig[3] ^= 1
	if err := VerifySig(env, sender.Signer.Public()); err == nil {
		t.Fatal("tampered sig verified")
	}
	// and sig must cover ct: flip ct, keep sig
	env2 := seal(t, sender, recipient, []byte("x"))
	env2.CT[0] ^= 1
	if err := VerifySig(env2, sender.Signer.Public()); err == nil {
		t.Fatal("sig did not cover ct")
	}
}

func TestWrongRecipientFails(t *testing.T) {
	sender, recipient, other := kp(t, identity.AlgoP256), kp(t, identity.AlgoP256), kp(t, identity.AlgoP256)
	env := seal(t, sender, recipient, []byte("secret"))
	if _, err := Open(other, env); err == nil {
		t.Fatal("wrong recipient opened the envelope")
	}
	if !strings.Contains(ErrInvalid.Error(), "envelope_invalid") {
		t.Fatal("sentinel should carry the wire code")
	}
}

func TestCanonicalHeaderSortedAndCompact(t *testing.T) {
	sender, recipient := kp(t, identity.AlgoP256), kp(t, identity.AlgoP256)
	env := seal(t, sender, recipient, []byte("x"))
	// keys in lexicographic order, no spaces, unpadded b64url members
	keys := []string{"cty", "exp", "from", "kid", "msg_id", "suite", "to", "ts", "v"}
	last := -1
	for _, k := range keys {
		i := bytes.Index(env.Protected, []byte(`"`+k+`"`))
		if i < 0 || i < last {
			t.Fatalf("key %q missing or out of order in %s", k, env.Protected)
		}
		last = i
	}
	if bytes.Contains(env.Protected, []byte(": ")) {
		t.Fatal("insignificant whitespace in canonical header")
	}
	// wire form: four b64url members
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"protected", "enc", "ct", "sig"} {
		v, ok := m[member]
		if !ok || strings.ContainsAny(v, "+/=") {
			t.Fatalf("member %q missing or not unpadded base64url", member)
		}
	}
	var back Envelope
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(recipient, &back); err != nil {
		t.Fatalf("wire round trip broke the envelope: %v", err)
	}
}

func TestECDSASigIsASN1DER(t *testing.T) {
	sender, recipient := kp(t, identity.AlgoP256), kp(t, identity.AlgoP256)
	env := seal(t, sender, recipient, []byte("x"))
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(env.Sig, &parsed); err != nil {
		t.Fatalf("ECDSA sig is not ASN.1 DER: %v", err)
	}
}

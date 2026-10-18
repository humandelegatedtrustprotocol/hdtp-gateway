package webhooks

import (
	"regexp"
	"strings"
	"testing"
)

// The signature a receiver verifies (the cloud's test/webhooks.test.ts, "the signature a customer
// verifies", case for case).

func sign(t *testing.T, secrets []string, body string, ts int64) string {
	t.Helper()
	h, err := Signature(secrets, body, ts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTheTimestampIsInsideWhatIsSigned(t *testing.T) {
	const secret, body = "whsec_test", `{"a":1}`
	header := sign(t, []string{secret}, body, 1_757_462_400)
	if !regexp.MustCompile(`^t=1757462400,v1=[0-9a-f]{64}$`).MatchString(header) {
		t.Fatalf("header %q is not t=<s>,v1=<hex>", header)
	}
	// Rewriting the timestamp in the header, which is the whole replay attack, invalidates the
	// signature rather than moving the window.
	tampered := strings.Replace(header, "t=1757462400", "t=1757462999", 1)
	if VerifySignature(secret, body, tampered, 1_757_462_999) {
		t.Fatal("a rewritten timestamp verified")
	}
	if got := SignedPayload(1_757_462_400, body); got != "1757462400."+body {
		t.Fatalf("signed payload %q", got)
	}
	// The control: the header as signed verifies.
	if !VerifySignature(secret, body, header, 1_757_462_400) {
		t.Fatal("the header as signed did not verify")
	}
	// And it is plain HMAC-SHA256 keyed by the secret's bytes, `whsec_` included, as the cloud's
	// is: the value below is `openssl dgst -sha256 -hmac whsec_test` over `1757462400.{"a":1}`
	// (Node's crypto.createHmac agrees), so a receiver's off-the-shelf HMAC verifies it.
	if want := "t=1757462400,v1=46854b8ac6551e9c9239b70c0a055dc6f36f3a9b8ed3c8481ce1b48dca330222"; header != want {
		t.Fatalf("header %q, want %q", header, want)
	}
}

func TestASignatureIsAcceptedInsideTheWindowAndRefusedOutsideIt(t *testing.T) {
	const secret, body, ts = "whsec_test", `{"a":1}`, int64(1_757_462_400)
	header := sign(t, []string{secret}, body, ts)
	for _, c := range []struct {
		at   int64
		want bool
	}{
		{ts, true},
		{ts + ToleranceSeconds, true},
		{ts - ToleranceSeconds, true},
		// A capture replayed later is refused, which is the point of the timestamp, and a clock
		// that has run backwards is refused symmetrically.
		{ts + ToleranceSeconds + 1, false},
		{ts - ToleranceSeconds - 1, false},
	} {
		if got := VerifySignature(secret, body, header, c.at); got != c.want {
			t.Errorf("at %d: verified %v, want %v", c.at, got, c.want)
		}
	}
}

func TestAChangedBodyAWrongSecretAndAMalformedHeaderAreRefused(t *testing.T) {
	header := sign(t, []string{"whsec_a"}, `{"a":1}`, 1_757_462_400)
	if VerifySignature("whsec_a", `{"a":2}`, header, 1_757_462_400) {
		t.Error("a changed body verified")
	}
	if VerifySignature("whsec_b", `{"a":1}`, header, 1_757_462_400) {
		t.Error("a wrong secret verified")
	}
	f64 := strings.Repeat("f", 64)
	for _, bad := range []string{"", "nonsense", "t=abc,v1=" + f64, "t=1757462400", "v1=" + f64, "t=1.5,v1=" + f64} {
		if VerifySignature("whsec_a", `{"a":1}`, bad, 1_757_462_400) {
			t.Errorf("the header %q verified", bad)
		}
	}
	if _, ok := ParseSignatureHeader("t=1757462400,v1=short"); ok {
		t.Error("a v1 that is not 64 hex digits parsed")
	}
	if _, err := Signature(nil, "{}", 1); err == nil {
		t.Error("signed with no secret")
	}
}

// The whole value of the dual-accept window in one assertion: a receiver still on the old secret
// and one already on the new both verify the same delivery.
func TestARotationSignsWithBothSecrets(t *testing.T) {
	const body, ts = `{"a":1}`, int64(1_757_462_400)
	header := sign(t, []string{"whsec_new", "whsec_old"}, body, ts)
	p, ok := ParseSignatureHeader(header)
	if !ok || len(p.Signatures) != 2 || p.Timestamp != ts {
		t.Fatalf("parsed %+v %v, want two signatures at %d", p, ok, ts)
	}
	if !VerifySignature("whsec_new", body, header, ts) || !VerifySignature("whsec_old", body, header, ts) {
		t.Fatal("one of the two secrets does not verify")
	}
	if VerifySignature("whsec_third", body, header, ts) {
		t.Fatal("a third secret verified")
	}
	// The new secret signs first.
	if !strings.HasPrefix(header, "t=1757462400,v1="+hmacHex("whsec_new", SignedPayload(ts, body))+",") {
		t.Fatalf("the new secret's signature is not first: %s", header)
	}
}

func TestASigningSecretLooksLikeOneAndIsNotGuessable(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		s, err := NewSigningSecret()
		if err != nil {
			t.Fatal(err)
		}
		// 32 bytes of base64url is 43 characters: a shorter secret is a test failure rather than
		// a quiet weakening.
		if !strings.HasPrefix(s, "whsec_") || len(s) != len("whsec_")+43 || strings.ContainsAny(s, "+/=") {
			t.Fatalf("secret %q is not whsec_ and 43 base64url characters", s)
		}
		seen[s] = true
	}
	if len(seen) != 20 {
		t.Fatalf("20 secrets minted, %d distinct", len(seen))
	}
}

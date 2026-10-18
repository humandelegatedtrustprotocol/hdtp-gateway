package webhooks

// Signing an outbound webhook, and the header a receiver verifies. Ported from BatonDeck's
// gateway/src/webhooks/sign.ts with the same grammar, so a receiver written for one host verifies
// the other:
//
//	X-HDTP-Signature: t=1757462400,v1=9f86d081884c7d659a2feaa0c55ad015…
//
// The signed string is `<t>.<body>`. A timestamp outside the signature would let anybody replay a
// captured delivery for ever by rewriting it; inside the body it would be unverifiable without
// parsing JSON the receiver has not yet trusted.
//
// `v1` may appear twice: while a rotation lasts both secrets sign one body, `v1=<new>,v1=<old>`, so
// a receiver checking either keeps working across the change.
//
// The receiver's verifier is in verify_test.go: the node never verifies its own deliveries, and the
// tests check the signer against the rules a receiver is told to implement.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	// SignatureHeader carries `t=<seconds>,v1=<hmac>[,v1=<hmac>]`.
	SignatureHeader = "X-HDTP-Signature"
	// EventIDHeader carries the event id, stable for a given event.
	EventIDHeader = "X-HDTP-Event-Id"
	// EventTypeHeader carries the event name.
	EventTypeHeader = "X-HDTP-Event-Type"
	// DeliveryHeader carries the delivery id, the key of one row of the delivery log.
	DeliveryHeader = "X-HDTP-Delivery"
)

// ToleranceSeconds is how far out of step a delivery's timestamp may be, each way, before a
// receiver should refuse it. It is the receiver's rule, not the node's; a verifier that omits it
// accepts a replay of any delivery ever captured.
const ToleranceSeconds = 300

// SignedPayload is the signed string: the one thing the two sides must agree on.
func SignedPayload(timestamp int64, body string) string {
	return strconv.FormatInt(timestamp, 10) + "." + body
}

// Signature is the header value for a body, over one or two secrets: two while a rotation is in
// its window, the new secret first, because a receiver that stops at the first `v1` should be
// stopping at the current one. The HMAC key is the secret's bytes as written, `whsec_` included.
func Signature(secrets []string, body string, timestamp int64) (string, error) {
	if len(secrets) == 0 {
		return "", errors.New("webhooks: cannot sign with no secret")
	}
	payload := SignedPayload(timestamp, body)
	var b strings.Builder
	b.WriteString("t=" + strconv.FormatInt(timestamp, 10))
	for _, s := range secrets {
		b.WriteString(",v1=" + hmacHex(s, payload))
	}
	return b.String(), nil
}

func hmacHex(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// NewSigningSecret is a signing secret: `whsec_` and 32 random bytes, base64url without padding.
// It is shown once, at creation and at rotation.
func NewSigningSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b), nil
}

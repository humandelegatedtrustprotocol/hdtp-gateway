package testid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// CardSigs is one card signed by an Ed25519 host key the test holds the seed of, with its honest
// `card_sig` and the second spellings and signatures a strict reader must refuse (HDTP §3, §13.1).
type CardSigs struct {
	// Host is the host whose leaf the card carries; its leaf certifies the key that signed the card.
	Host *Host
	// Card is the card text the signatures are over.
	Card string
	// Honest is the RFC 8032 signature, unpadded base64url: the control that must get through.
	Honest string
	// Refused names each other `card_sig` for the same card by what is wrong with it.
	Refused map[string]string
}

// SignedCardSigs builds CardSigs for a fresh leaf of w at endpoint.
func SignedCardSigs(t testing.TB, w *Wallet, endpoint, fn string) CardSigs {
	t.Helper()
	// Keys until the signature's standard-alphabet spelling differs from its base64url one (a
	// sextet of 62 or 63; about one signature in sixteen has none), so that case is always tested.
	for range 64 {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		h := w.IssueOver(t, endpoint, spki)
		card := h.Card(fn, "")
		sig := ed25519.Sign(priv, []byte(card))
		std := base64.RawStdEncoding.EncodeToString(sig)
		if !strings.ContainsAny(std, "+/") {
			continue
		}
		honest := base64.RawURLEncoding.EncodeToString(sig)
		return CardSigs{Host: h, Card: card, Honest: honest, Refused: map[string]string{
			"padded":                               base64.URLEncoding.EncodeToString(sig),
			"the standard alphabet":                std,
			"spare low bits in the last character": SpareBits(t, honest),
			"a line break inside":                  honest[:40] + "\r\n" + honest[40:],
			"R of small order":                     base64.RawURLEncoding.EncodeToString(SmallOrderR(t, priv, []byte(card))),
		}}
	}
	t.Fatal("testid: 64 signatures and none spelled differently in the standard alphabet")
	return CardSigs{}
}

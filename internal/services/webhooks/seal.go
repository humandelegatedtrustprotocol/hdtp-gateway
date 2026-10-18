package webhooks

// Sealing an endpoint's signing secret. The node signs every delivery with it, so it cannot be
// hashed the way a password is: it is a stored, recoverable secret, and it is sealed with the
// node's keyring (core.Keyring, the only write path for secrets at rest), as
// integrations.SealOAuth seals an integration's tokens. The cloud seals it under the workspace's
// data key with the workspace id as additional data (BatonDeck's gateway/src/webhooks/seal.ts).
//
// The additional data is the account and the endpoint, so a blob moved between rows, by a bug or
// by hand, fails to open rather than opening as somebody else's secret. It does not name the
// column: a rotation moves the current blob into previous_sealed in one statement
// (queries/*/webhooks.sql RotateWebhookSecret), and the previous secret must still open there for
// the dual signature to be made.

import (
	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

// Sealer is the keyring slice this package needs (core.Keyring satisfies it).
type Sealer interface {
	Encrypt(plaintext, aad []byte) ([]byte, error)
	Decrypt(sealed, aad []byte) ([]byte, error)
}

func secretAAD(accountID, endpointID string) []byte {
	return []byte("webhook-secret:" + accountID + ":" + endpointID)
}

func (s *Service) seal(accountID, endpointID, secret string) ([]byte, error) {
	return s.kr.Encrypt([]byte(secret), secretAAD(accountID, endpointID))
}

func (s *Service) open(accountID, endpointID string, sealed []byte) (string, error) {
	plain, err := s.kr.Decrypt(sealed, secretAAD(accountID, endpointID))
	return string(plain), err
}

// SecretsFor is what a delivery to e is signed with at now (unix milliseconds): its secret, then
// the one a rotation replaced while that is still accepted. A secret that will not open is an
// error, so nothing is signed with a secret a receiver cannot hold; the cloud signs with the
// current one alone when only the previous will not open, and so does this, reporting
// previousLost true.
func (s *Service) SecretsFor(e store.WebhookEndpoint, now int64) (secrets []string, previousLost bool, err error) {
	current, err := s.open(e.AccountID, e.ID, e.SecretSealed)
	if err != nil {
		return nil, false, err
	}
	secrets = []string{current}
	if e.PreviousSealed != nil && e.PreviousUntil > now {
		previous, err := s.open(e.AccountID, e.ID, e.PreviousSealed)
		if err != nil {
			return secrets, true, nil
		}
		secrets = append(secrets, previous)
	}
	return secrets, false, nil
}

package auth

// Bearer tokens for the owner MCP (SPEC §3.4): named, revocable, hashed at rest,
// owner- or account-scoped. The plaintext is returned exactly once at creation;
// lists never contain secrets; revocation takes effect on the next request.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/humandelegatedtrustprotocol/hdtp-gateway/internal/core/store"
)

const tokenPrefix = "hdtp_"

// TokenService mints, validates, revokes and lists the bearer tokens of the owner MCP. A token is
// "hdtp_" followed by 48 hex characters; only its SHA-256 is stored.
type TokenService struct {
	// Store holds the token rows (hashes and metadata).
	Store store.OwnerStore
	// Now is the clock for creation and revocation times; nil means time.Now.
	Now func() time.Time
}

func (t *TokenService) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Create mints a token for ownerID, optionally scoped to one account.
// The returned plaintext is the ONLY time the secret exists outside a hash.
func (t *TokenService) Create(ctx context.Context, ownerID, label, accountID string) (plaintext string, id string, err error) {
	if label == "" {
		return "", "", errors.New("auth: token label required")
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	plaintext = tokenPrefix + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	idb := make([]byte, 8)
	if _, err := rand.Read(idb); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(idb)
	if err := t.Store.InsertToken(ctx, id, ownerID, label, sum[:], accountID, t.now().Unix()); err != nil {
		return "", "", err
	}
	return plaintext, id, nil
}

// Identity is what a validated token acts as (SPEC §3.4): the owner, optionally
// narrowed to one account.
type Identity struct {
	// OwnerID is the owner the token was minted for.
	OwnerID   string
	AccountID string // "" = all the owner's accounts
}

// Validate resolves a presented bearer to its identity; error on unknown,
// malformed, or revoked tokens.
//
// There is no comparison step, by design: the lookup is BY the SHA-256 of the
// presented token, so a token that does not exist simply does not resolve, and
// the store never sees a plaintext to compare. This used to end with a
// `subtle.ConstantTimeCompare(sum[:], sum[:])` labelled "paranoia" — which
// compares a value with itself and is therefore always 1. It protected nothing
// and read like an authentication control, which is worse than not being there.
func (t *TokenService) Validate(ctx context.Context, presented string) (Identity, error) {
	if !strings.HasPrefix(presented, tokenPrefix) {
		return Identity{}, errors.New("auth: not an hdtp token")
	}
	sum := sha256.Sum256([]byte(presented))
	row, err := t.Store.GetTokenByHash(ctx, sum[:])
	if err != nil {
		return Identity{}, errors.New("auth: unknown token")
	}
	if row.RevokedAt != 0 {
		return Identity{}, errors.New("auth: token revoked")
	}
	return Identity{OwnerID: row.OwnerID, AccountID: row.AccountID}, nil
}

// Revoke marks the token with this id revoked, effective on the next Validate. The SQLite store
// refuses an id that is missing or already revoked (TestTokenLifecycle holds the second case).
func (t *TokenService) Revoke(ctx context.Context, id string) error {
	return t.Store.RevokeToken(ctx, id, t.now().Unix())
}

// TokenInfo is a token as List answers it: metadata only, no hash and no plaintext.
type TokenInfo struct {
	// ID is the token's id, what Revoke takes and the audit trail's token:<id> names.
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	// Label is the name the owner gave it.
	Label string `json:"label"`
	// AccountID is the account the token is narrowed to; omitted for a token that spans every
	// account its owner administers.
	AccountID string `json:"account_id,omitempty"`
	// CreatedAt is unix seconds.
	CreatedAt int64 `json:"created_at"`
	// Revoked is true once Revoke has run; a revoked token stays listed.
	Revoked bool `json:"revoked"`
}

// List returns metadata only — never hashes, never plaintexts.
func (t *TokenService) List(ctx context.Context) ([]TokenInfo, error) {
	rows, err := t.Store.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]TokenInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, TokenInfo{
			ID: r.ID, OwnerID: r.OwnerID, Label: r.Label, AccountID: r.AccountID,
			CreatedAt: r.CreatedAt, Revoked: r.RevokedAt != 0,
		})
	}
	return out, nil
}

var _ = fmt.Sprintf

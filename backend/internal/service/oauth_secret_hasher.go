package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const oauthLegacyHashKeyVersion = 1

// OAuthSecretHash binds a credential digest to the key version that produced it.
type OAuthSecretHash struct {
	Version int
	Hash    string
}

// OAuthSecretHasher signs new credentials with the current HMAC key and keeps
// bounded read compatibility for the previous HMAC key plus legacy v1 SHA-256.
type OAuthSecretHasher struct {
	currentVersion  int
	currentKey      []byte
	previousVersion int
	previousKey     []byte
}

func NewOAuthSecretHasher(cfg config.OAuthServerConfig) (*OAuthSecretHasher, error) {
	if cfg.HashKeyVersion < 2 || len(cfg.HashKey) < 32 {
		return nil, ErrInvalidRequest
	}
	if cfg.PreviousHashKeyVersion != 0 && (cfg.PreviousHashKeyVersion < 2 || cfg.PreviousHashKeyVersion >= cfg.HashKeyVersion || len(cfg.PreviousHashKey) < 32) {
		return nil, ErrInvalidRequest
	}
	if cfg.PreviousHashKeyVersion == 0 && cfg.PreviousHashKey != "" {
		return nil, ErrInvalidRequest
	}
	return &OAuthSecretHasher{
		currentVersion:  cfg.HashKeyVersion,
		currentKey:      []byte(cfg.HashKey),
		previousVersion: cfg.PreviousHashKeyVersion,
		previousKey:     []byte(cfg.PreviousHashKey),
	}, nil
}

func hashOAuthSecretHMAC(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *OAuthSecretHasher) Current(value string) OAuthSecretHash {
	return OAuthSecretHash{Version: h.currentVersion, Hash: hashOAuthSecretHMAC(h.currentKey, value)}
}

func (h *OAuthSecretHasher) Candidates(value string) []OAuthSecretHash {
	out := []OAuthSecretHash{h.Current(value)}
	if h.previousVersion != 0 {
		out = append(out, OAuthSecretHash{Version: h.previousVersion, Hash: hashOAuthSecretHMAC(h.previousKey, value)})
	}
	return append(out, OAuthSecretHash{Version: oauthLegacyHashKeyVersion, Hash: HashOAuthSecret(value)})
}

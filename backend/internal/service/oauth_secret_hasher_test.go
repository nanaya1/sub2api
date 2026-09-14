package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestOAuthSecretHasherUsesVersionedHMACAndRetainsLegacyV1(t *testing.T) {
	cfg := config.OAuthServerConfig{
		HashKeyVersion:         2,
		HashKey:                "0123456789abcdef0123456789abcdef",
		PreviousHashKeyVersion: 0,
	}
	hasher, err := NewOAuthSecretHasher(cfg)
	require.NoError(t, err)

	mac := hmac.New(sha256.New, []byte(cfg.HashKey))
	_, _ = mac.Write([]byte("secret"))
	wantV2 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	current := hasher.Current("secret")
	require.Equal(t, 2, current.Version)
	require.Equal(t, wantV2, current.Hash)
	require.NotEqual(t, HashOAuthSecret("secret"), current.Hash)

	candidates := hasher.Candidates("secret")
	require.Contains(t, candidates, OAuthSecretHash{Version: 2, Hash: wantV2})
	require.Contains(t, candidates, OAuthSecretHash{Version: 1, Hash: HashOAuthSecret("secret")})
}

func TestOAuthSecretHasherSupportsPreviousHMACKeyDuringRotation(t *testing.T) {
	cfg := config.OAuthServerConfig{
		HashKeyVersion:         3,
		HashKey:                "33333333333333333333333333333333",
		PreviousHashKeyVersion: 2,
		PreviousHashKey:        "22222222222222222222222222222222",
	}
	hasher, err := NewOAuthSecretHasher(cfg)
	require.NoError(t, err)

	candidates := hasher.Candidates("secret")
	require.Len(t, candidates, 3)
	require.Equal(t, 3, candidates[0].Version)
	require.Equal(t, 2, candidates[1].Version)
	require.Equal(t, 1, candidates[2].Version)
}

func TestOAuthSecretHasherRejectsUnsafeConfiguration(t *testing.T) {
	_, err := NewOAuthSecretHasher(config.OAuthServerConfig{HashKeyVersion: 2, HashKey: "short"})
	require.Error(t, err)

	_, err = NewOAuthSecretHasher(config.OAuthServerConfig{
		HashKeyVersion:         3,
		HashKey:                "33333333333333333333333333333333",
		PreviousHashKeyVersion: 2,
	})
	require.Error(t, err)
}

package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type revokeRepoStub struct {
	OAuthServerRepository
	hashes []OAuthSecretHash
	client string
}

func (r *revokeRepoStub) RevokeCredential(_ context.Context, hashes []OAuthSecretHash, client string, _ time.Time) error {
	r.hashes = hashes
	r.client = client
	return nil
}
func TestOAuthRevokeService(t *testing.T) {
	r := &revokeRepoStub{}
	s := NewOAuthServerService(r)
	require.NoError(t, s.Revoke(context.Background(), "secret", ""))
	// 2026-09-14：撤销必须覆盖当前 HMAC 与 legacy v1。
	require.Len(t, r.hashes, 2)
	require.Equal(t, OAuthSecretHash{Version: 1, Hash: HashOAuthSecret("secret")}, r.hashes[1])
	require.Empty(t, r.client)
	require.ErrorIs(t, s.Revoke(context.Background(), "", ""), ErrInvalidRequest)
}

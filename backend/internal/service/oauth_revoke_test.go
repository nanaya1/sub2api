package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type revokeRepoStub struct {
	OAuthServerRepository
	hash, client string
}

func (r *revokeRepoStub) RevokeCredential(_ context.Context, hash, client string, _ time.Time) error {
	r.hash = hash
	r.client = client
	return nil
}
func TestOAuthRevokeService(t *testing.T) {
	r := &revokeRepoStub{}
	s := NewOAuthServerService(r)
	require.NoError(t, s.Revoke(context.Background(), "secret", ""))
	require.Equal(t, HashOAuthSecret("secret"), r.hash)
	require.Empty(t, r.client)
	require.ErrorIs(t, s.Revoke(context.Background(), "", ""), ErrInvalidRequest)
}

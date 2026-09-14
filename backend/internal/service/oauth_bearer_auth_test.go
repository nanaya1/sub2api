package service

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type bearerRepoStub struct {
	OAuthRepository
	tokens []OAuthSecretHash
	now    time.Time
}

func (r *bearerRepoStub) FindActiveAccessToken(_ context.Context, hashes []OAuthSecretHash, now time.Time) (*AccessTokenRecord, error) {
	r.tokens = hashes
	r.now = now
	return &AccessTokenRecord{UserID: 7, ClientID: 3, FamilyID: uuid.New(), Scopes: []string{"profile"}, ExpiresAt: now.Add(time.Hour)}, nil
}
func TestOAuthAuthenticateBearer(t *testing.T) {
	r := &bearerRepoStub{}
	s := NewOAuthServerService(r)
	s.Now = func() time.Time { return time.Unix(100, 0) }
	got, err := s.AuthenticateBearer(context.Background(), "secret")
	require.NoError(t, err)
	require.Equal(t, int64(7), got.UserID)
	// 2026-09-14：原单摘要断言改为当前 HMAC + legacy v1 候选。
	// require.Equal(t, HashOAuthSecret("secret"), r.token)
	require.Len(t, r.tokens, 2)
	require.Equal(t, 2, r.tokens[0].Version)
	require.Equal(t, OAuthSecretHash{Version: 1, Hash: HashOAuthSecret("secret")}, r.tokens[1])
	_, err = s.AuthenticateBearer(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidRequest)
}

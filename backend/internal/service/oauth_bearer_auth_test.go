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
	token string
	now   time.Time
}

func (r *bearerRepoStub) FindActiveAccessToken(_ context.Context, hash string, now time.Time) (*AccessTokenRecord, error) {
	r.token = hash
	r.now = now
	return &AccessTokenRecord{UserID: 7, ClientID: 3, FamilyID: uuid.New(), Scopes: []string{"openid"}, ExpiresAt: now.Add(time.Hour)}, nil
}
func TestOAuthAuthenticateBearer(t *testing.T) {
	r := &bearerRepoStub{}
	s := NewOAuthServerService(r)
	s.Now = func() time.Time { return time.Unix(100, 0) }
	got, err := s.AuthenticateBearer(context.Background(), "secret")
	require.NoError(t, err)
	require.Equal(t, int64(7), got.UserID)
	require.Equal(t, HashOAuthSecret("secret"), r.token)
	_, err = s.AuthenticateBearer(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidRequest)
}

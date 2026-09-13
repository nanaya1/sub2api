package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type exchangeRepoStub struct {
	OAuthServerRepository
	code    OAuthCodeExchange
	refresh OAuthRefreshExchange
	fail    bool
}

func (r *exchangeRepoStub) ExchangeCode(_ context.Context, in OAuthCodeExchange) (*OAuthIssuedGrant, error) {
	r.code = in
	if r.fail {
		return nil, ErrInvalidGrant
	}
	return &OAuthIssuedGrant{Scopes: []string{"profile", "offline_access"}, AccessExpiresAt: in.Now.Add(in.AccessTTL)}, nil
}
func (r *exchangeRepoStub) RotateRefresh(_ context.Context, in OAuthRefreshExchange) (*OAuthIssuedGrant, error) {
	r.refresh = in
	if r.fail {
		return nil, ErrInvalidGrant
	}
	return &OAuthIssuedGrant{Scopes: []string{"profile", "offline_access"}, AccessExpiresAt: in.Now.Add(time.Minute)}, nil
}
func TestOAuthTokenExchangeService(t *testing.T) {
	r := &exchangeRepoStub{}
	s := NewOAuthServerService(r)
	out, err := s.ExchangeCode(context.Background(), "desktop", "code", "meacowork://oauth/callback", "verifier")
	require.NoError(t, err)
	require.Equal(t, "Bearer", out.TokenType)
	require.Equal(t, int64(900), out.ExpiresIn)
	require.Equal(t, HashOAuthSecret("code"), r.code.CodeHash)
	require.Equal(t, HashOAuthSecret(out.AccessToken), r.code.AccessHash)
	require.Equal(t, HashOAuthSecret(out.RefreshToken), r.code.RefreshHash)
	next, err := s.Refresh(context.Background(), "desktop", out.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, int64(60), next.ExpiresIn)
	require.NotEqual(t, out.RefreshToken, next.RefreshToken)
	require.Equal(t, HashOAuthSecret(out.RefreshToken), r.refresh.TokenHash)
	r.fail = true
	out, err = s.Refresh(context.Background(), "desktop", "bad")
	require.ErrorIs(t, err, ErrInvalidGrant)
	require.Nil(t, out)
}

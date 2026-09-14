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
	// 2026-09-14：授权码读取包含 v2 HMAC 与 legacy v1；新 token 只写 v2 HMAC。
	require.Len(t, r.code.CodeHashes, 2)
	require.Equal(t, OAuthSecretHash{Version: 1, Hash: HashOAuthSecret("code")}, r.code.CodeHashes[1])
	require.Equal(t, 2, r.code.AccessHashVersion)
	require.Equal(t, s.hasher.Current(out.AccessToken).Hash, r.code.AccessHash)
	require.Equal(t, 2, r.code.RefreshHashVersion)
	require.Equal(t, s.hasher.Current(out.RefreshToken).Hash, r.code.RefreshHash)
	next, err := s.Refresh(context.Background(), "desktop", out.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, int64(60), next.ExpiresIn)
	require.NotEqual(t, out.RefreshToken, next.RefreshToken)
	require.Len(t, r.refresh.TokenHashes, 2)
	require.Equal(t, OAuthSecretHash{Version: 1, Hash: HashOAuthSecret(out.RefreshToken)}, r.refresh.TokenHashes[1])
	r.fail = true
	out, err = s.Refresh(context.Background(), "desktop", "bad")
	require.ErrorIs(t, err, ErrInvalidGrant)
	require.Nil(t, out)
}

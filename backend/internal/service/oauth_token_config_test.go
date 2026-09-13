package service

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOAuthConfiguredTTLs(t *testing.T) {
	r := &exchangeRepoStub{}
	c := config.OAuthServerConfig{AccessTokenTTL: 2 * time.Minute, RefreshTokenAbsoluteTTL: 24 * time.Hour, RefreshTokenIdleTTL: time.Hour}
	s, err := NewConfiguredOAuthServerService(r, c)
	require.NoError(t, err)
	response, err := s.ExchangeCode(context.Background(), "desktop", "code", "meacowork://oauth/callback", "verifier")
	require.NoError(t, err)
	require.Equal(t, int64(120), response.ExpiresIn)
	require.Equal(t, c.RefreshTokenAbsoluteTTL, r.code.RefreshTTL)
	require.Equal(t, c.RefreshTokenIdleTTL, r.code.IdleTTL)
	_, err = s.Refresh(context.Background(), "desktop", "refresh")
	require.NoError(t, err)
	require.Equal(t, c.AccessTokenTTL, r.refresh.AccessTTL)
	require.Equal(t, c.RefreshTokenIdleTTL, r.refresh.IdleTTL)
	c.RefreshTokenIdleTTL = 48 * time.Hour
	_, err = NewConfiguredOAuthServerService(r, c)
	require.Error(t, err)
}

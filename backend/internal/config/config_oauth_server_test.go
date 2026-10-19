package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// 2026-10-19：issuer 已移除，遗留配置不应阻止 OAuth Server 启动。
func TestOAuthServerIgnoresRemovedIssuer(t *testing.T) {
	for _, issuer := range []string{"", "not-an-absolute-url", "ftp://legacy.example.com"} {
		t.Run(issuer, func(t *testing.T) {
			resetViperWithJWTSecret(t)
			viper.Set("oauth_server.enabled", true)
			viper.Set("oauth_server.client_id", "xuelang-client")
			viper.Set("oauth_server.redirect_uri", "meacowork://oauth/callback")
			viper.Set("oauth_server.hash_key", "0123456789abcdef0123456789abcdef")
			viper.Set("oauth_server.issuer", issuer)
			_, err := Load()
			require.NoError(t, err)
		})
	}
}

// 2026-10-19：默认兼容 HTTP，环境变量可显式开启 Secure。
func TestOAuthServerCookieSecure(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	// 2026-10-19：按用户要求默认 false，HTTPS 可显式开启。
	// require.True(t, cfg.OAuthServer.CookieSecure)
	require.False(t, cfg.OAuthServer.CookieSecure)
	// t.Setenv("OAUTH_SERVER_COOKIE_SECURE", "false")
	t.Setenv("OAUTH_SERVER_COOKIE_SECURE", "true")
	cfg, err = Load()
	require.NoError(t, err)
	// require.False(t, cfg.OAuthServer.CookieSecure)
	require.True(t, cfg.OAuthServer.CookieSecure)
}

// 以下测试覆盖批次 0：OAuth Authorization Server 配置与功能开关。
// 不改动现有 oidc_connect（外部 IdP）配置，不与 Gateway 路由耦合。

func TestOAuthServerDisabledByDefault(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.False(t, cfg.OAuthServer.Enabled, "oauth_server must be disabled by default")
}

func TestOAuthServerDefaultTTLsAndPKCE(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)

	require.Equal(t, 60*time.Second, cfg.OAuthServer.AuthorizationCodeTTL,
		"authorization code ttl must default to 60s")
	require.Equal(t, 15*time.Minute, cfg.OAuthServer.AccessTokenTTL,
		"access token ttl must default to 15m")
	require.Equal(t, 720*time.Hour, cfg.OAuthServer.RefreshTokenAbsoluteTTL,
		"refresh token absolute ttl must default to 30d (720h)")
	require.Equal(t, 168*time.Hour, cfg.OAuthServer.RefreshTokenIdleTTL,
		"refresh token idle ttl must default to 7d (168h)")
	require.True(t, cfg.OAuthServer.RequirePKCES256,
		"only S256 PKCE must be allowed by default")
}

func TestOAuthServerRejectsEmptyClientIDWhenEnabled(t *testing.T) {
	resetViperWithJWTSecret(t)
	viper.Set("oauth_server.enabled", true)
	viper.Set("oauth_server.client_id", "")
	viper.Set("oauth_server.redirect_uri", "meacowork://oauth/callback")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "oauth_server.client_id")
}

func TestOAuthServerRejectsNonS256WhenEnabled(t *testing.T) {
	resetViperWithJWTSecret(t)
	viper.Set("oauth_server.enabled", true)
	viper.Set("oauth_server.client_id", "xuelang-client")
	viper.Set("oauth_server.redirect_uri", "meacowork://oauth/callback")
	viper.Set("oauth_server.require_pkce_s256", false)

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "require_pkce_s256")
}

func TestOAuthServerRejectsCodeTTLAbove120s(t *testing.T) {
	resetViperWithJWTSecret(t)
	// 硬上限无论开关是否启用都应生效。
	viper.Set("oauth_server.authorization_code_ttl", "121s")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "authorization_code_ttl")
}

func TestOAuthServerRejectsIllegalRefreshIdleTTL(t *testing.T) {
	resetViperWithJWTSecret(t)
	// idle ttl 不能超过 absolute ttl。
	viper.Set("oauth_server.refresh_token_absolute_ttl", "24h")
	viper.Set("oauth_server.refresh_token_idle_ttl", "72h")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "refresh_token_idle_ttl")
}

func TestOAuthServerRejectsMissingHashKeyWhenEnabled(t *testing.T) {
	resetViperWithJWTSecret(t)
	viper.Set("oauth_server.enabled", true)
	viper.Set("oauth_server.client_id", "xuelang-client")
	viper.Set("oauth_server.redirect_uri", "meacowork://oauth/callback")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "oauth_server.hash_key")
}

func TestOAuthServerEnabledWithValidConfigPasses(t *testing.T) {
	resetViperWithJWTSecret(t)
	viper.Set("oauth_server.enabled", true)
	viper.Set("oauth_server.client_id", "xuelang-client")
	viper.Set("oauth_server.redirect_uri", "meacowork://oauth/callback")
	// 2026-09-14：OAuth 启用后必须注入至少 32 字节的 HMAC 密钥。
	viper.Set("oauth_server.hash_key", "0123456789abcdef0123456789abcdef")

	_, err := Load()
	require.NoError(t, err)
}

// 以下为批次 0 复核要求的 TDD 失败用例（先红后绿）。

func TestOAuthServerRejectsWrongRedirectURIWhenEnabled(t *testing.T) {
	resetViperWithJWTSecret(t)
	viper.Set("oauth_server.enabled", true)
	viper.Set("oauth_server.client_id", "xuelang-client")
	viper.Set("oauth_server.redirect_uri", "https://evil.example.com/cb")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "oauth_server.redirect_uri")
}

func TestOAuthServerRejectsEmptyRedirectURIWhenEnabled(t *testing.T) {
	resetViperWithJWTSecret(t)
	viper.Set("oauth_server.enabled", true)
	viper.Set("oauth_server.client_id", "xuelang-client")
	viper.Set("oauth_server.redirect_uri", "")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "oauth_server.redirect_uri")
}

func TestOAuthServerRejectsCodeTTLBelow1s(t *testing.T) {
	resetViperWithJWTSecret(t)
	// 错误信息声称 1s，但旧实现仅 <=0 才报错，允许 500ms/1ns 等亚秒值。
	viper.Set("oauth_server.authorization_code_ttl", "500ms")

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "authorization_code_ttl")
}

func TestOAuthServerAcceptsCodeTTLExactly1s(t *testing.T) {
	resetViperWithJWTSecret(t)
	// >=1s 应被接受。
	viper.Set("oauth_server.authorization_code_ttl", "1s")

	_, err := Load()
	require.NoError(t, err)
}

func TestOAuthServerRejectsAccessTTLExceedingRefreshAbsolute(t *testing.T) {
	resetViperWithJWTSecret(t)
	// access_token_ttl 不得超过 refresh_token_absolute_ttl（无论开关是否启用）。
	viper.Set("oauth_server.access_token_ttl", "800h")
	viper.Set("oauth_server.refresh_token_absolute_ttl", "720h") // 30d

	_, err := Load()
	require.Error(t, err)
	require.ErrorContains(t, err, "access_token_ttl")
}

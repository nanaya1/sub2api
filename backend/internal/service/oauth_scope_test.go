package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScopesWhitespaceSeparatedAndDedup(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "openid", []string{"openid"}},
		{"space separated", "openid profile email", []string{"openid", "profile", "email"}},
		{"tabs and newlines", "  openid\tprofile\nemail ", []string{"openid", "profile", "email"}},
		{"duplicates removed", "openid openid profile", []string{"openid", "profile"}},
		{"case sensitive dedup", "OpenID openid", []string{"OpenID", "openid"}},
	}
	for _, cc := range cases {
		t.Run(cc.name, func(t *testing.T) {
			assert.Equal(t, cc.want, ParseScopes(cc.raw))
		})
	}
}

func TestValidateScopesToleratesIgnored(t *testing.T) {
	// 2026-09-14：openid 按"容忍但忽略"处理——OpenAI 式客户端写死携带，
	// 校验不拒绝，入口 StripIgnoredScopes 剔除后入库。
	require.NoError(t, ValidateScopes([]string{"openid"}))
	require.NoError(t, ValidateScopes([]string{"openid", "profile", "balance:read"}))

	// 真正未知的 scope 仍然拒绝。
	err := ValidateScopes([]string{"profile", "unknown_scope"})
	require.Error(t, err)
	var oe *OAuthError
	require.ErrorAs(t, err, &oe)
	assert.Equal(t, "invalid_scope", oe.Code)
}

func TestStripIgnoredScopes(t *testing.T) {
	assert.Equal(t, []string{"profile", "email"}, StripIgnoredScopes([]string{"openid", "profile", "email"}))
	assert.Equal(t, []string{"profile"}, StripIgnoredScopes([]string{"profile", "openid"}))
	assert.Equal(t, []string{"profile", "openid2"}, StripIgnoredScopes([]string{"profile", "openid2"}))
	assert.Empty(t, StripIgnoredScopes([]string{"openid", "openid"}))
	assert.Empty(t, StripIgnoredScopes(nil))
	// 大小写敏感：OpenID 不是可忽略 scope
	assert.Equal(t, []string{"OpenID"}, StripIgnoredScopes([]string{"OpenID"}))
}

func TestIsSubsetCaseSensitive(t *testing.T) {
	// openid 不在 OAuthServerScopes 中——授权入口已 StripIgnoredScopes 剔除，
	// IsSubset 只处理剔除后的列表，因此 openid + profile 对白名单仍是 false。
	require.True(t, IsSubset([]string{"profile", "email"}, OAuthServerScopes))
	require.False(t, IsSubset([]string{"openid", "profile"}, OAuthServerScopes))
	// 大小写敏感：OpenID 不等于 openid
	require.False(t, IsSubset([]string{"OpenID"}, []string{"openid"}))
	// 空集是任意集合的子集
	require.True(t, IsSubset(nil, OAuthServerScopes))
}

func TestOAuthServerScopesContainsFixedSet(t *testing.T) {
	// 2026-09-14：原固定集合中的 openid 移除，直到服务端实际签发 id_token。
	// want := []string{"openid", "profile", "email", "offline_access", ...}
	want := []string{
		"profile", "email", "offline_access", "balance:read",
		"usage:read", "tokens:read", "tokens:write",
	}
	require.Equal(t, want, OAuthServerScopes)
}

func TestHasScope(t *testing.T) {
	granted := []string{"openid", "profile", "tokens:read"}
	require.True(t, HasScope(granted, "tokens:read"))
	require.True(t, HasScope(granted, "openid"))
	require.False(t, HasScope(granted, "balance:read"))
	require.False(t, HasScope(granted, "tokens:write"))
	// 大小写敏感
	require.False(t, HasScope(granted, "Tokens:Read"))
	require.False(t, HasScope(nil, "tokens:read"))
}

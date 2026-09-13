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

func TestValidateScopesRejectsUnknown(t *testing.T) {
	require.NoError(t, ValidateScopes([]string{"openid", "profile", "balance:read"}))

	err := ValidateScopes([]string{"openid", "unknown_scope"})
	require.Error(t, err)
	var oe *OAuthError
	require.ErrorAs(t, err, &oe)
	assert.Equal(t, "invalid_scope", oe.Code)
}

func TestIsSubsetCaseSensitive(t *testing.T) {
	require.True(t, IsSubset([]string{"openid", "profile"}, OAuthServerScopes))
	require.False(t, IsSubset([]string{"openid", "not_exist"}, OAuthServerScopes))
	// 大小写敏感：OpenID 不等于 openid
	require.False(t, IsSubset([]string{"OpenID"}, []string{"openid"}))
	// 空集是任意集合的子集
	require.True(t, IsSubset(nil, OAuthServerScopes))
}

func TestOAuthServerScopesContainsFixedSet(t *testing.T) {
	want := []string{
		"openid", "profile", "email", "offline_access",
		"balance:read", "usage:read", "tokens:read", "tokens:write",
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

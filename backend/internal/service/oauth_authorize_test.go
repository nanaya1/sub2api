package service

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestValidateOAuthAuthorizeRequest(t *testing.T) {
	now := time.Unix(100, 0)
	// 2026-09-14：openid 未签发 id_token，合法授权请求改用 profile；原断言注释保留。
	// require.NoError(t, ValidateOAuthAuthorizeRequest("code", "client", "https://app/cb", "https://app/cb", "openid", "S256", strings.Repeat("a", 43), now.Add(time.Minute), now))
	require.NoError(t, ValidateOAuthAuthorizeRequest("code", "client", "https://app/cb", "https://app/cb", "profile", "S256", strings.Repeat("a", 43), now.Add(time.Minute), now))
	tests := []struct{ name, response, client, redirect, expected, scope, method, challenge string }{
		{"response type", "token", "client", "https://app/cb", "https://app/cb", "openid", "S256", strings.Repeat("a", 43)},
		{"redirect", "code", "client", "https://evil", "https://app/cb", "openid", "S256", strings.Repeat("a", 43)},
		{"method", "code", "client", "https://app/cb", "https://app/cb", "openid", "plain", strings.Repeat("a", 43)},
		{"scope", "code", "client", "https://app/cb", "https://app/cb", "admin", "S256", strings.Repeat("a", 43)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, ValidateOAuthAuthorizeRequest(tt.response, tt.client, tt.redirect, tt.expected, tt.scope, tt.method, tt.challenge, now.Add(time.Minute), now))
		})
	}
}

package service

import (
	"strings"
)

// OAuthServerScopes 是雪浪 OAuth Authorization Server 第一轮固定支持的 scope 集合。
// 注意：当前客户端虽可携带 openid，但本批不实现 OIDC，不签发 id_token。
var OAuthServerScopes = []string{
	"openid",
	"profile",
	"email",
	"offline_access",
	"balance:read",
	"usage:read",
	"tokens:read",
	"tokens:write",
}

// allowedScopeSet 供 O(1) 查找。
var allowedScopeSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(OAuthServerScopes))
	for _, s := range OAuthServerScopes {
		m[s] = struct{}{}
	}
	return m
}()

// ParseScopes 按空白（空格/制表符/换行）分隔解析 scope 字符串，
// 去除每项首尾空白并按首次出现顺序去重（大小写敏感，不去小写化）。
func ParseScopes(raw string) []string {
	seen := make(map[string]struct{}, 8)
	var out []string
	for _, part := range strings.Fields(raw) {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ValidateScopes 校验每个 scope 都属于固定支持集合（大小写敏感）。
// 遇到未知 scope 返回 ErrInvalidScope（invalid_scope）。
func ValidateScopes(scopes []string) error {
	for _, s := range scopes {
		if _, ok := allowedScopeSet[s]; !ok {
			return ErrInvalidScope
		}
	}
	return nil
}

// IsSubset 判断 requested 是否为 allowed 的大小写敏感子集。
// 空集始终是任意集合的子集。
func IsSubset(requested, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allowedSet[s]; !ok {
			return false
		}
	}
	return true
}

// HasScope 判断 granted 中是否包含所需 scope。
func HasScope(granted []string, want string) bool {
	for _, s := range granted {
		if s == want {
			return true
		}
	}
	return false
}

package service

import (
	"strings"
)

// OAuthServerScopes 是雪浪 OAuth Authorization Server 第一轮固定支持的 scope 集合。
// 2026-09-14：本服务不签发 id_token，因此不宣称支持 openid；但兼容写死 openid
// 的 OpenAI 式客户端（如 Cherry Studio gateway / MeacoWork）——openid 按可忽略
// scope 容忍：校验不拒绝，入库/授权前剔除（见 IgnoredScopes / StripIgnoredScopes）。
var OAuthServerScopes = []string{
	"profile",
	"email",
	"offline_access",
	"balance:read",
	"usage:read",
	"tokens:read",
	"tokens:write",
}

// IgnoredScopes 是"容忍但不宣称"的 scope：客户端可以携带，服务端不校验、
// 不写入授权记录、也不赋予任何权限。openid 属于此类——本服务暂不实现
// OIDC、不签发 id_token，因此不能把 openid 记入 granted scopes（会在
// refresh/exchange 的 allowed_scopes @> 子集校验中留下永远无法满足的承诺）。
var IgnoredScopes = []string{
	"openid",
}

// isIgnoredScope 判断 s 是否属于可忽略 scope。
func isIgnoredScope(s string) bool {
	for _, ig := range IgnoredScopes {
		if s == ig {
			return true
		}
	}
	return false
}

// StripIgnoredScopes 返回剔除可忽略 scope 后的列表（保持原顺序）。
// 供授权入口在白名单校验和事务入库前调用，保证 transaction.scopes、
// consent 展示与 oauth_consents.granted 全部不含 openid。
func StripIgnoredScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if isIgnoredScope(s) {
			continue
		}
		out = append(out, s)
	}
	return out
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

// ValidateScopes 校验每个 scope 都属于固定支持集合或可忽略集合（大小写敏感）。
// 可忽略 scope（openid）不报错——由入口调用方 StripIgnoredScopes 剔除；
// 遇到真正未知的 scope 返回 ErrInvalidScope（invalid_scope）。
func ValidateScopes(scopes []string) error {
	for _, s := range scopes {
		if isIgnoredScope(s) {
			continue
		}
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

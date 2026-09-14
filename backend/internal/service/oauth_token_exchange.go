package service

import (
	"context"
	"time"
)

// OAuthTokenResponse is returned only after the repository transaction commits.
// It must never be included in logs, metrics labels, or audit payloads.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func (s *OAuthServerService) ExchangeCode(ctx context.Context, clientID, code, redirect, verifier string) (*OAuthTokenResponse, error) {
	if clientID == "" || code == "" || len(code) > 1024 || len(clientID) > 128 {
		return nil, ErrInvalidRequest
	}
	if s.hasher == nil {
		return nil, ErrServerError
	}
	return s.issue(ctx, func(access, refresh OAuthSecretHash, now time.Time) (*OAuthIssuedGrant, error) {
		// 2026-09-14：原 CodeHash 单摘要改为版本化候选，新 token 显式写当前 HMAC 版本。
		// return s.Repo.ExchangeCode(ctx, OAuthCodeExchange{CodeHash: HashOAuthSecret(code), ...})
		return s.Repo.ExchangeCode(ctx, OAuthCodeExchange{CodeHashes: s.hasher.Candidates(code), ClientID: clientID, RedirectURI: redirect, Verifier: verifier, AccessHash: access.Hash, RefreshHash: refresh.Hash, AccessHashVersion: access.Version, RefreshHashVersion: refresh.Version, Now: now, AccessTTL: s.accessTTL, RefreshTTL: s.refreshTTL, IdleTTL: s.idleTTL})
	})
}
func (s *OAuthServerService) Refresh(ctx context.Context, clientID, token string) (*OAuthTokenResponse, error) {
	if clientID == "" || token == "" || len(token) > 1024 || len(clientID) > 128 {
		return nil, ErrInvalidRequest
	}
	if s.hasher == nil {
		return nil, ErrServerError
	}
	return s.issue(ctx, func(access, refresh OAuthSecretHash, now time.Time) (*OAuthIssuedGrant, error) {
		// 2026-09-14：原 refresh token 单摘要改为版本化候选。
		// return s.Repo.RotateRefresh(ctx, OAuthRefreshExchange{TokenHash: HashOAuthSecret(token), ...})
		return s.Repo.RotateRefresh(ctx, OAuthRefreshExchange{TokenHashes: s.hasher.Candidates(token), ClientID: clientID, AccessHash: access.Hash, RefreshHash: refresh.Hash, AccessHashVersion: access.Version, RefreshHashVersion: refresh.Version, Now: now, AccessTTL: s.accessTTL, IdleTTL: s.idleTTL})
	})
}
func (s *OAuthServerService) issue(ctx context.Context, commit func(OAuthSecretHash, OAuthSecretHash, time.Time) (*OAuthIssuedGrant, error)) (*OAuthTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	access, err := GenerateOAuthSecret()
	if err != nil {
		return nil, err
	}
	refresh, err := GenerateOAuthSecret()
	if err != nil {
		return nil, err
	}
	now := s.now()
	// 2026-09-14：原无密钥摘要写入改为当前 HMAC 版本。
	// grant, err := commit(HashOAuthSecret(access), HashOAuthSecret(refresh), now)
	grant, err := commit(s.hasher.Current(access), s.hasher.Current(refresh), now)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, ErrServerError
	}
	expires := int64(grant.AccessExpiresAt.Sub(now) / time.Second)
	if expires < 1 {
		return nil, ErrInvalidGrant
	}
	if !IsSubset([]string{"offline_access"}, grant.Scopes) {
		refresh = ""
	}
	return &OAuthTokenResponse{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: expires, Scope: OAuthScopeString(grant.Scopes)}, nil
}

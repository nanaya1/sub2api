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
	return s.issue(ctx, func(access, refresh string, now time.Time) (*OAuthIssuedGrant, error) {
		return s.Repo.ExchangeCode(ctx, OAuthCodeExchange{CodeHash: HashOAuthSecret(code), ClientID: clientID, RedirectURI: redirect, Verifier: verifier, AccessHash: access, RefreshHash: refresh, Now: now, AccessTTL: s.accessTTL, RefreshTTL: s.refreshTTL, IdleTTL: s.idleTTL})
	})
}
func (s *OAuthServerService) Refresh(ctx context.Context, clientID, token string) (*OAuthTokenResponse, error) {
	if clientID == "" || token == "" || len(token) > 1024 || len(clientID) > 128 {
		return nil, ErrInvalidRequest
	}
	return s.issue(ctx, func(access, refresh string, now time.Time) (*OAuthIssuedGrant, error) {
		return s.Repo.RotateRefresh(ctx, OAuthRefreshExchange{TokenHash: HashOAuthSecret(token), ClientID: clientID, AccessHash: access, RefreshHash: refresh, Now: now, AccessTTL: s.accessTTL, IdleTTL: s.idleTTL})
	})
}
func (s *OAuthServerService) issue(ctx context.Context, commit func(string, string, time.Time) (*OAuthIssuedGrant, error)) (*OAuthTokenResponse, error) {
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
	grant, err := commit(HashOAuthSecret(access), HashOAuthSecret(refresh), now)
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

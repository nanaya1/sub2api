package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/google/uuid"
)

const (
	OAuthAuthorizationCodeTTL = time.Minute
	OAuthAccessTokenTTL       = 15 * time.Minute
	OAuthRefreshAbsoluteTTL   = 30 * 24 * time.Hour
	OAuthRefreshIdleTTL       = 7 * 24 * time.Hour
)

type OAuthRepository interface {
	FindActiveAccessToken(context.Context, string, time.Time) (*AccessTokenRecord, error)
	RevokeCredential(context.Context, string, string, time.Time) error
	ExchangeCode(context.Context, OAuthCodeExchange) (*OAuthIssuedGrant, error)
	RotateRefresh(context.Context, OAuthRefreshExchange) (*OAuthIssuedGrant, error)
	RevokeFamily(context.Context, uuid.UUID, time.Time) error
}
type OAuthServerService struct {
	Repo                           OAuthRepository
	Now                            func() time.Time
	accessTTL, refreshTTL, idleTTL time.Duration
}

func (s *OAuthServerService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}
func NewOAuthServerService(r OAuthRepository) *OAuthServerService {
	return &OAuthServerService{Repo: r, accessTTL: OAuthAccessTokenTTL, refreshTTL: OAuthRefreshAbsoluteTTL, idleTTL: OAuthRefreshIdleTTL}
}

// NewConfiguredOAuthServerService is the production constructor. Routing and
// startup configuration must independently enforce Enabled and client policy.
func NewConfiguredOAuthServerService(r OAuthRepository, cfg config.OAuthServerConfig) (*OAuthServerService, error) {
	if r == nil || cfg.AccessTokenTTL < time.Second || cfg.RefreshTokenAbsoluteTTL < cfg.AccessTokenTTL || cfg.RefreshTokenIdleTTL < time.Second || cfg.RefreshTokenIdleTTL > cfg.RefreshTokenAbsoluteTTL {
		return nil, ErrInvalidRequest
	}
	return &OAuthServerService{Repo: r, accessTTL: cfg.AccessTokenTTL, refreshTTL: cfg.RefreshTokenAbsoluteTTL, idleTTL: cfg.RefreshTokenIdleTTL}, nil
}
func GenerateOAuthSecret() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func HashOAuthSecret(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func VerifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || len(challenge) != 43 {
		return false
	}
	for _, c := range verifier {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	h := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
func ValidateOAuthCodeInput(redirect, expected, verifier, challenge, method string, expiry, now time.Time) error {
	if redirect != expected || method != "S256" || !VerifyPKCE(verifier, challenge) || !expiry.After(now) {
		return ErrInvalidGrant
	}
	return nil
}
func ValidateOAuthScopes(requested, granted []string) error {
	if err := ValidateScopes(requested); err != nil {
		return err
	}
	if !IsSubset(requested, granted) {
		return ErrInvalidScope
	}
	return nil
}
func OAuthScopeString(v []string) string { return strings.Join(v, " ") }

func (s *OAuthServerService) AuthenticateBearer(ctx context.Context, token string) (*AccessTokenRecord, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrInvalidRequest
	}
	r, err := s.Repo.FindActiveAccessToken(ctx, HashOAuthSecret(token), s.now())
	if err != nil {
		return nil, ErrInvalidGrant
	}
	return r, nil
}

func (s *OAuthServerService) Revoke(ctx context.Context, credential, clientID string) error {
	if strings.TrimSpace(credential) == "" {
		return ErrInvalidRequest
	}
	return s.Repo.RevokeCredential(ctx, HashOAuthSecret(credential), clientID, s.now())
}

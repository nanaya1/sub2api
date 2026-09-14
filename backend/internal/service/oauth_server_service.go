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
	// 2026-09-14：凭据读取按 hash_key_version + hash 候选匹配；旧单摘要签名注释保留。
	// FindActiveAccessToken(context.Context, string, time.Time) (*AccessTokenRecord, error)
	FindActiveAccessToken(context.Context, []OAuthSecretHash, time.Time) (*AccessTokenRecord, error)
	// RevokeCredential(context.Context, string, string, time.Time) error
	RevokeCredential(context.Context, []OAuthSecretHash, string, time.Time) error
	ExchangeCode(context.Context, OAuthCodeExchange) (*OAuthIssuedGrant, error)
	RotateRefresh(context.Context, OAuthRefreshExchange) (*OAuthIssuedGrant, error)
	RevokeFamily(context.Context, uuid.UUID, time.Time) error
}
type OAuthServerService struct {
	Repo                           OAuthRepository
	Now                            func() time.Time
	accessTTL, refreshTTL, idleTTL time.Duration
	hasher                         *OAuthSecretHasher
}

func (s *OAuthServerService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}
func NewOAuthServerService(r OAuthRepository) *OAuthServerService {
	// 2026-09-14：测试便捷构造器使用进程内随机密钥；生产必须使用下方配置构造器。
	key, err := GenerateOAuthSecret()
	if err != nil {
		return &OAuthServerService{Repo: r, accessTTL: OAuthAccessTokenTTL, refreshTTL: OAuthRefreshAbsoluteTTL, idleTTL: OAuthRefreshIdleTTL}
	}
	hasher, _ := NewOAuthSecretHasher(config.OAuthServerConfig{HashKeyVersion: 2, HashKey: key})
	return &OAuthServerService{Repo: r, accessTTL: OAuthAccessTokenTTL, refreshTTL: OAuthRefreshAbsoluteTTL, idleTTL: OAuthRefreshIdleTTL, hasher: hasher}
}

// NewConfiguredOAuthServerService is the production constructor. Routing and
// startup configuration must independently enforce Enabled and client policy.
func NewConfiguredOAuthServerService(r OAuthRepository, cfg config.OAuthServerConfig) (*OAuthServerService, error) {
	if !cfg.Enabled {
		return &OAuthServerService{Repo: r, accessTTL: cfg.AccessTokenTTL, refreshTTL: cfg.RefreshTokenAbsoluteTTL, idleTTL: cfg.RefreshTokenIdleTTL}, nil
	}
	if r == nil || cfg.AccessTokenTTL < time.Second || cfg.RefreshTokenAbsoluteTTL < cfg.AccessTokenTTL || cfg.RefreshTokenIdleTTL < time.Second || cfg.RefreshTokenIdleTTL > cfg.RefreshTokenAbsoluteTTL {
		return nil, ErrInvalidRequest
	}
	hasher, err := NewOAuthSecretHasher(cfg)
	if err != nil {
		return nil, err
	}
	return &OAuthServerService{Repo: r, accessTTL: cfg.AccessTokenTTL, refreshTTL: cfg.RefreshTokenAbsoluteTTL, idleTTL: cfg.RefreshTokenIdleTTL, hasher: hasher}, nil
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
	if strings.TrimSpace(token) == "" || s.hasher == nil {
		return nil, ErrInvalidRequest
	}
	// 2026-09-14：原 HashOAuthSecret(token) 单摘要查询改为版本化 HMAC 候选。
	// r, err := s.Repo.FindActiveAccessToken(ctx, HashOAuthSecret(token), s.now())
	r, err := s.Repo.FindActiveAccessToken(ctx, s.hasher.Candidates(token), s.now())
	if err != nil {
		return nil, ErrInvalidGrant
	}
	return r, nil
}

func (s *OAuthServerService) Revoke(ctx context.Context, credential, clientID string) error {
	if strings.TrimSpace(credential) == "" || s.hasher == nil {
		return ErrInvalidRequest
	}
	// 2026-09-14：撤销同时覆盖当前、上一版 HMAC 与 legacy v1。
	// return s.Repo.RevokeCredential(ctx, HashOAuthSecret(credential), clientID, s.now())
	return s.Repo.RevokeCredential(ctx, s.hasher.Candidates(credential), clientID, s.now())
}

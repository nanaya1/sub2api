package service

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// OAuthCodeExchange contains hashes only; raw credentials remain in the service.
type OAuthCodeExchange struct {
	// 2026-09-14：原单一 CodeHash 改为版本化候选，保留字段用于旧测试/调用兼容。
	CodeHash, ClientID, RedirectURI, Verifier string
	CodeHashes                                []OAuthSecretHash
	AccessHash, RefreshHash                   string
	AccessHashVersion, RefreshHashVersion     int
	Now                                       time.Time
	AccessTTL, RefreshTTL, IdleTTL            time.Duration
}

type OAuthIssuedGrant struct {
	UserID, ClientID                  int64
	FamilyID                          uuid.UUID
	Scopes                            []string
	AccessExpiresAt, RefreshExpiresAt time.Time
}

type OAuthRefreshExchange struct {
	// 2026-09-14：原 TokenHash 保留用于旧测试/调用兼容；生产路径使用 TokenHashes。
	TokenHash, ClientID, AccessHash, RefreshHash string
	TokenHashes                                  []OAuthSecretHash
	AccessHashVersion, RefreshHashVersion        int
	Now                                          time.Time
	AccessTTL, IdleTTL                           time.Duration
}

// OAuthResumeRepoInput is the repository-level atomic resume request. It binds
// the authenticated web user to a pending_login transaction. The caller (HTTP
// handler) supplies the real subject identity from the JWT session and the raw
// oauth_browser cookie; the repository re-validates both under a SQL row lock.
type OAuthResumeRepoInput struct {
	TransactionID  string
	UserID         int64
	BrowserSession string
	Now            time.Time
}

type OAuthServerRepository interface {
	OAuthClientReader
	OAuthTransactionCreator
	FindAuthorizationTransaction(context.Context, string) (*OAuthAuthorizationTransactionRecord, error)
	DecideAuthorizationTransaction(context.Context, OAuthDecisionRepoInput) (*OAuthDecisionRepoOutput, error)
	ResumeAuthorizationTransaction(context.Context, OAuthResumeRepoInput) error
	// 2026-09-14：原单摘要接口改为版本化候选；旧签名注释保留。
	// FindActiveAccessToken(context.Context, string, time.Time) (*AccessTokenRecord, error)
	FindActiveAccessToken(context.Context, []OAuthSecretHash, time.Time) (*AccessTokenRecord, error)
	// RevokeCredential(context.Context, string, string, time.Time) error
	RevokeCredential(context.Context, []OAuthSecretHash, string, time.Time) error
	RotateRefresh(context.Context, OAuthRefreshExchange) (*OAuthIssuedGrant, error)
	ExchangeCode(context.Context, OAuthCodeExchange) (*OAuthIssuedGrant, error)
	FindAuthorizationCode(context.Context, string) (*AuthorizationCodeRecord, error)
	ConsumeAuthorizationCode(context.Context, int64, time.Time) error
	FindRefreshToken(context.Context, string) (*RefreshTokenRecord, error)
	RevokeFamily(context.Context, uuid.UUID, time.Time) error
	StoreAccessToken(context.Context, AccessTokenRecord) error
	StoreRefreshToken(context.Context, RefreshTokenRecord) error
	RevokeAccessToken(context.Context, string, time.Time) error
}

type AuthorizationCodeRecord struct {
	ID, UserID, ClientID           int64
	RedirectURI, Challenge, Method string
	Scopes                         []string
	ExpiresAt                      time.Time
	ConsumedAt                     *time.Time
}
type AccessTokenRecord struct {
	Hash                string
	HashKeyVersion      int
	FamilyID            uuid.UUID
	UserID, ClientID    int64
	Scopes              []string
	IssuedAt, ExpiresAt time.Time
}
type RefreshTokenRecord struct {
	ID                                 int64
	Hash                               string
	FamilyID                           uuid.UUID
	UserID, ClientID                   int64
	Scopes                             []string
	IssuedAt, ExpiresAt, IdleExpiresAt time.Time
	RevokedAt                          *time.Time
	ReplacedBy                         *int64
}

package service

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

type OAuthTransactionInput struct {
	ClientID                                          int64
	RedirectURI                                       string
	Scopes                                            []string
	State, Challenge, ChallengeMethod, BrowserSession string
	Now                                               time.Time
	TTL                                               time.Duration
}
type OAuthAuthorizationTransactionRecord struct {
	UserID                                                                                                   int64
	TransactionID, RedirectURI, State, Challenge, ChallengeMethod, BrowserSessionHash, CSRFTokenHash, Status string
	// 2026-09-14：原字段 ClientID 是 oauth_clients.id 内部自增 FK，此前被当作 client_id 返回给
	// 授权确认页（页面上显示成 "1"）。现改为下方三个新字段；原字段注释保留、暂不删除。
	// ClientID                                                                                                 int64
	// ClientInternalID  = oauth_clients.id 外键（bigint，仅内部使用）
	// ClientExternalID  = 对外稳定的字符串 client_id（授权请求中使用的标识）
	// ClientName        = 注册的应用显示名（确认页展示）
	ClientInternalID             int64
	ClientExternalID, ClientName string
	Scopes                       []string
	ExpiresAt                    time.Time
}

// OAuthTransactionResult carries the created transaction together with the
// plaintext CSRF token. The plaintext CSRF MUST NOT be persisted; it is returned
// to the caller (and ultimately the browser's consent form) so it can be echoed
// back as the anti-CSRF credential on the consent POST. Only the HMAC hash of the
// CSRF is stored in the transaction row.
type OAuthTransactionResult struct {
	*OAuthAuthorizationTransactionRecord
	CSRFToken string
}

func NewOAuthAuthorizationTransaction(in OAuthTransactionInput) (*OAuthTransactionResult, error) {
	if in.ClientID <= 0 || in.RedirectURI == "" || in.State == "" || in.Challenge == "" || in.BrowserSession == "" || in.TTL <= 0 {
		return nil, ErrInvalidRequest
	}
	id, e := oauthRandom()
	if e != nil {
		return nil, e
	}
	csrf, e := oauthRandom()
	if e != nil {
		return nil, e
	}
	return &OAuthTransactionResult{
		OAuthAuthorizationTransactionRecord: &OAuthAuthorizationTransactionRecord{
			TransactionID:      id,
			// 2026-09-14：ClientID → ClientInternalID（原因见结构体注释），原行注释保留。
			// ClientID:           in.ClientID,
			ClientInternalID:   in.ClientID,
			RedirectURI:        in.RedirectURI,
			Scopes:             append([]string(nil), in.Scopes...),
			State:              in.State,
			Challenge:          in.Challenge,
			ChallengeMethod:    in.ChallengeMethod,
			BrowserSessionHash: HashOAuthSecret(in.BrowserSession),
			CSRFTokenHash:      HashOAuthSecret(csrf),
			Status:             "pending_login",
			ExpiresAt:          in.Now.Add(in.TTL),
		},
		CSRFToken: csrf,
	}, nil
}

// OAuthDecisionInput is the service-level consent decision request. The caller
// (HTTP handler) supplies the authenticated user identity and the CSRF token that
// was submitted in the form body. The identity MUST come from the web session,
// never from the transaction row, to avoid a transaction-owned user_id masquerading
// as the approver.
type OAuthDecisionInput struct {
	TransactionID  string
	UserID         int64
	Decision       string // "approve" | "deny"
	BrowserSession string // raw oauth_browser cookie value
	CSRFToken      string // raw CSRF submitted in the form body
}

// OAuthDecisionOutput is returned by the service only after the repository has
// committed the decision. Code is the plaintext authorization code (empty on
// deny); RedirectURI and State are echoed so the handler can redirect the browser
// back to the OAuth client.
type OAuthDecisionOutput struct {
	Code        string
	RedirectURI string
	State       string
}

// OAuthResumeInput is the service-level resume request. The caller (HTTP handler)
// supplies the authenticated subject (from the JWT web session) and the raw
// oauth_browser cookie value. The service forwards both to the repository, which
// re-validates them under a SQL row lock before binding the user.
type OAuthResumeInput struct {
	TransactionID  string
	UserID         int64
	BrowserSession string
}

// OAuthDecisionRepoInput is the repository-level atomic decision request. The
// service pre-computes the authorization code hash (on approve) so the repository
// only ever stores the hash, never the plaintext code.
type OAuthDecisionRepoInput struct {
	TransactionID  string
	UserID         int64
	Decision       string
	BrowserSession string
	CSRFToken      string
	CodeHash       string
	CodeTTL        time.Duration
	Now            time.Time
}

// OAuthDecisionRepoOutput is returned by the repository after commit. Code is
// intentionally empty: the repository does not hold the plaintext code, the
// service attaches it once the transaction is committed.
type OAuthDecisionRepoOutput struct {
	RedirectURI string
	State       string
}

func oauthRandom() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

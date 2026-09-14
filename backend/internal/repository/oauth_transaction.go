package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/ent/oauthauthorizationtransaction"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *oauthServerRepository) FindAuthorizationTransaction(ctx context.Context, id string) (*service.OAuthAuthorizationTransactionRecord, error) {
	if r.client != nil {
		// 2026-09-14：原查询不带关联，ClientID 只能取到内部 FK；现增加 WithClient() 预加载，
		// 以便带出注册应用名与对外 client_id。原查询注释保留、暂不删除。
		// x, e := r.client.OAuthAuthorizationTransaction.Query().Where(oauthauthorizationtransaction.TransactionIDEQ(id)).Only(ctx)
		x, e := r.client.OAuthAuthorizationTransaction.Query().Where(oauthauthorizationtransaction.TransactionIDEQ(id)).WithClient().Only(ctx)
		if e != nil {
			return nil, e
		}
		// 2026-09-14：字段映射调整 ClientID→ClientInternalID，并新增 ClientExternalID/ClientName（原因见 service 结构体注释）。
		// 原映射注释保留、暂不删除。
		// out := &service.OAuthAuthorizationTransactionRecord{TransactionID: x.TransactionID, ClientID: x.ClientID, RedirectURI: x.RedirectURI, Scopes: x.RequestedScopes, State: x.State, Challenge: x.CodeChallenge, ChallengeMethod: x.CodeChallengeMethod, BrowserSessionHash: x.BrowserSessionHash, CSRFTokenHash: x.CsrfTokenHash, Status: x.Status, ExpiresAt: x.ExpiresAt}
		out := &service.OAuthAuthorizationTransactionRecord{TransactionID: x.TransactionID, ClientInternalID: x.ClientID, ClientExternalID: x.Edges.Client.ClientID, ClientName: x.Edges.Client.Name, RedirectURI: x.RedirectURI, Scopes: x.RequestedScopes, State: x.State, Challenge: x.CodeChallenge, ChallengeMethod: x.CodeChallengeMethod, BrowserSessionHash: x.BrowserSessionHash, CSRFTokenHash: x.CsrfTokenHash, Status: x.Status, ExpiresAt: x.ExpiresAt}
		if x.UserID != nil {
			out.UserID = *x.UserID
		}
		return out, nil
	}
	// Raw-SQL fallback joins oauth_clients so the consent screen can show the
	// registered application name and external client_id instead of the internal
	// bigint FK (which previously leaked as "1" on the consent page).
	//
	// 2026-09-14：fallback 查询改为 LEFT JOIN oauth_clients，带出对外 client_id 与应用名；
	// SELECT 列序对应关系：t.client_id → ClientInternalID，c.client_id → ClientExternalID，
	// c.name → ClientName。原单表查询注释保留、暂不删除。
	// e := r.sql.QueryRowContext(ctx, "SELECT id, transaction_id, redirect_uri, requested_scopes, state, code_challenge, code_challenge_method, browser_session_hash, csrf_token_hash, user_id, status, expires_at, consumed_at, client_id FROM oauth_authorization_transactions WHERE transaction_id = $1", id).Scan(new(int64), &out.TransactionID, &out.RedirectURI, &raw, &out.State, &out.Challenge, &out.ChallengeMethod, &out.BrowserSessionHash, &out.CSRFTokenHash, &user, &out.Status, &exp, &consumed, &out.ClientID)
	var out service.OAuthAuthorizationTransactionRecord
	var raw []byte
	var exp sql.NullTime
	var consumed sql.NullTime
	var user sql.NullInt64
	var clientExternalID, clientName sql.NullString
	e := r.sql.QueryRowContext(ctx, `SELECT t.transaction_id, t.redirect_uri, t.requested_scopes, t.state, t.code_challenge, t.code_challenge_method, t.browser_session_hash, t.csrf_token_hash, t.user_id, t.status, t.expires_at, t.consumed_at, t.client_id, c.client_id, c.name FROM oauth_authorization_transactions t LEFT JOIN oauth_clients c ON c.id = t.client_id WHERE t.transaction_id = $1`, id).Scan(&out.TransactionID, &out.RedirectURI, &raw, &out.State, &out.Challenge, &out.ChallengeMethod, &out.BrowserSessionHash, &out.CSRFTokenHash, &user, &out.Status, &exp, &consumed, &out.ClientInternalID, &clientExternalID, &clientName)
	if e != nil {
		return nil, e
	}
	if user.Valid {
		out.UserID = user.Int64
	}
	_ = json.Unmarshal(raw, &out.Scopes)
	if exp.Valid {
		out.ExpiresAt = exp.Time
	}
	out.ClientExternalID = clientExternalID.String
	out.ClientName = clientName.String
	return &out, nil
}

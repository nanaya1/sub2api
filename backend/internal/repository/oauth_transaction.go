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
		x, e := r.client.OAuthAuthorizationTransaction.Query().Where(oauthauthorizationtransaction.TransactionIDEQ(id)).Only(ctx)
		if e != nil {
			return nil, e
		}
		out := &service.OAuthAuthorizationTransactionRecord{TransactionID: x.TransactionID, ClientID: x.ClientID, RedirectURI: x.RedirectURI, Scopes: x.RequestedScopes, State: x.State, Challenge: x.CodeChallenge, ChallengeMethod: x.CodeChallengeMethod, BrowserSessionHash: x.BrowserSessionHash, CSRFTokenHash: x.CsrfTokenHash, Status: x.Status, ExpiresAt: x.ExpiresAt}
		if x.UserID != nil {
			out.UserID = *x.UserID
		}
		return out, nil
	}
	var out service.OAuthAuthorizationTransactionRecord
	var raw []byte
	var exp sql.NullTime
	var consumed sql.NullTime
	var user sql.NullInt64
	e := r.sql.QueryRowContext(ctx, "SELECT id, transaction_id, redirect_uri, requested_scopes, state, code_challenge, code_challenge_method, browser_session_hash, csrf_token_hash, user_id, status, expires_at, consumed_at, client_id FROM oauth_authorization_transactions WHERE transaction_id = $1", id).Scan(new(int64), &out.TransactionID, &out.RedirectURI, &raw, &out.State, &out.Challenge, &out.ChallengeMethod, &out.BrowserSessionHash, &out.CSRFTokenHash, &user, &out.Status, &exp, &consumed, &out.ClientID)
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
	return &out, nil
}

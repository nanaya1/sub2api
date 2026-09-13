package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

// ExchangeCode locks and consumes a code in the same transaction that creates
// its token pair. Any write failure leaves the code unconsumed.
func (r *oauthServerRepository) ExchangeCode(ctx context.Context, in service.OAuthCodeExchange) (*service.OAuthIssuedGrant, error) {
	if in.AccessTTL <= 0 || in.RefreshTTL < in.AccessTTL || in.IdleTTL <= 0 || in.IdleTTL > in.RefreshTTL {
		return nil, service.ErrInvalidRequest
	}
	tx, err := r.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id, userID, clientID int64
	var redirect, challenge, method string
	var scopesJSON []byte
	var expires sql.NullTime
	var consumed sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT c.id, c.user_id, c.client_id, c.redirect_uri,
 c.code_challenge, c.code_challenge_method, c.scopes, c.expires_at, c.consumed_at
 FROM oauth_authorization_codes c
 JOIN oauth_clients cl ON cl.id = c.client_id
 JOIN users u ON u.id = c.user_id
 JOIN oauth_consents co ON co.client_id = c.client_id AND co.user_id = c.user_id
 WHERE c.code_hash = $1 AND cl.client_id = $2
 AND cl.status = 'active' AND cl.client_type = 'public' AND cl.require_pkce = TRUE
 AND u.status = 'active' AND u.deleted_at IS NULL AND co.revoked_at IS NULL
 AND co.scopes @> c.scopes AND cl.allowed_scopes @> c.scopes
 AND cl.allowed_grant_types @> '["authorization_code"]'::jsonb
 FOR UPDATE OF c, cl, u, co`, in.CodeHash, in.ClientID).Scan(&id, &userID, &clientID, &redirect, &challenge, &method, &scopesJSON, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if consumed.Valid || !expires.Valid {
		return nil, service.ErrInvalidGrant
	}
	if err = service.ValidateOAuthCodeInput(in.RedirectURI, redirect, in.Verifier, challenge, method, expires.Time, in.Now); err != nil {
		return nil, err
	}
	var scopes []string
	if err = json.Unmarshal(scopesJSON, &scopes); err != nil {
		return nil, err
	}
	if err = service.ValidateScopes(scopes); err != nil {
		return nil, err
	}
	family := uuid.New()
	accessExpiry := in.Now.Add(in.AccessTTL)
	refreshExpiry := in.Now.Add(in.RefreshTTL)
	if _, err = tx.ExecContext(ctx, `UPDATE oauth_authorization_codes SET consumed_at=$1, updated_at=$1 WHERE id=$2`, in.Now, id); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_access_tokens
 (token_hash, family_id, user_id, client_id, scopes, issued_at, expires_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7)`, in.AccessHash, family, userID, clientID, string(scopesJSON), in.Now, accessExpiry); err != nil {
		return nil, err
	}
	if service.IsSubset([]string{"offline_access"}, scopes) {
		if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_refresh_tokens
  (token_hash, family_id, user_id, client_id, scopes, issued_at, expires_at, idle_expires_at)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, in.RefreshHash, family, userID, clientID, string(scopesJSON), in.Now, refreshExpiry, in.Now.Add(in.IdleTTL)); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &service.OAuthIssuedGrant{UserID: userID, ClientID: clientID, FamilyID: family, Scopes: scopes, AccessExpiresAt: accessExpiry, RefreshExpiresAt: refreshExpiry}, nil
}

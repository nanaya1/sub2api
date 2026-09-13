package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

// RotateRefresh serializes all changes to a family with the same lock used by
// RevokeFamily. The post-lock read observes a concurrent rotation or revocation.
func (r *oauthServerRepository) RotateRefresh(ctx context.Context, in service.OAuthRefreshExchange) (*service.OAuthIssuedGrant, error) {
	if in.AccessTTL <= 0 || in.IdleTTL <= 0 {
		return nil, service.ErrInvalidRequest
	}
	tx, err := r.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var family uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT t.family_id FROM oauth_refresh_tokens t JOIN oauth_clients cl ON cl.id=t.client_id WHERE t.token_hash=$1 AND cl.client_id=$2`, in.TokenHash, in.ClientID).Scan(&family)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "oauth-family:"+family.String()); err != nil {
		return nil, err
	}
	var id, userID, clientID int64
	var scopesJSON []byte
	var expires, idle, revoked, lastUsed sql.NullTime
	var replaced sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT t.id,t.user_id,t.client_id,t.scopes,t.expires_at,t.idle_expires_at,t.revoked_at,t.replaced_by_token_id,t.last_used_at
 FROM oauth_refresh_tokens t
 JOIN oauth_clients cl ON cl.id=t.client_id
 JOIN users u ON u.id=t.user_id
 JOIN oauth_consents co ON co.client_id=t.client_id AND co.user_id=t.user_id
 WHERE t.token_hash=$1 AND cl.client_id=$2
 AND cl.status='active' AND cl.client_type='public' AND cl.require_pkce=TRUE
 AND u.status='active' AND u.deleted_at IS NULL AND co.revoked_at IS NULL
 AND co.scopes @> t.scopes AND cl.allowed_scopes @> t.scopes
 AND cl.allowed_grant_types @> '["refresh_token"]'::jsonb
 FOR UPDATE OF t,cl,u,co`, in.TokenHash, in.ClientID).Scan(&id, &userID, &clientID, &scopesJSON, &expires, &idle, &revoked, &replaced, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	// Even after a rotated token expires, reuse must revoke its live descendants.
	// last_used_at remains a consumption marker if a replacement FK is later cleared.
	if replaced.Valid || lastUsed.Valid {
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET revoked_at=$1,updated_at=$1 WHERE family_id=$2 AND revoked_at IS NULL`, in.Now, family); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_access_tokens SET revoked_at=$1,updated_at=$1 WHERE family_id=$2 AND revoked_at IS NULL`, in.Now, family); err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, service.ErrInvalidGrant
	}
	if revoked.Valid || !expires.Valid || !expires.Time.After(in.Now) || idle.Valid && !idle.Time.After(in.Now) {
		return nil, service.ErrInvalidGrant
	}
	var scopes []string
	if err = json.Unmarshal(scopesJSON, &scopes); err != nil {
		return nil, err
	}
	if err = service.ValidateScopes(scopes); err != nil {
		return nil, err
	}
	accessExpiry := in.Now.Add(in.AccessTTL)
	if accessExpiry.After(expires.Time) {
		accessExpiry = expires.Time
	}
	idleExpiry := in.Now.Add(in.IdleTTL)
	if idleExpiry.After(expires.Time) {
		idleExpiry = expires.Time
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_access_tokens (token_hash,family_id,user_id,client_id,scopes,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, in.AccessHash, family, userID, clientID, string(scopesJSON), in.Now, accessExpiry); err != nil {
		return nil, err
	}
	var nextID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO oauth_refresh_tokens (token_hash,family_id,user_id,client_id,scopes,issued_at,expires_at,idle_expires_at,parent_token_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, in.RefreshHash, family, userID, clientID, string(scopesJSON), in.Now, expires.Time, idleExpiry, id).Scan(&nextID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE oauth_refresh_tokens SET last_used_at=$1,updated_at=$1,replaced_by_token_id=$2 WHERE id=$3`, in.Now, nextID, id); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &service.OAuthIssuedGrant{UserID: userID, ClientID: clientID, FamilyID: family, Scopes: scopes, AccessExpiresAt: accessExpiry, RefreshExpiresAt: expires.Time}, nil
}

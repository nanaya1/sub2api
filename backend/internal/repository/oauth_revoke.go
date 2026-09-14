package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"time"
)

// RevokeCredential accepts either credential type. The hint is deliberately not
// used as an authorization decision. An optional external client ID narrows lookup.
// Expired/disabled credentials can still revoke their family.
func (r *oauthServerRepository) RevokeCredential(ctx context.Context, candidates []service.OAuthSecretHash, clientID string, now time.Time) error {
	candidatesJSON, encodeErr := oauthHashCandidatesJSON(candidates, "")
	if encodeErr != nil {
		return service.ErrInvalidRequest
	}
	var family uuid.UUID
	// 2026-09-14：撤销查询从单摘要改为版本 + 摘要候选。
	err := r.sql.QueryRowContext(ctx, `SELECT family_id FROM (
 SELECT t.family_id FROM oauth_access_tokens t JOIN oauth_clients c ON c.id=t.client_id
 WHERE EXISTS (SELECT 1 FROM jsonb_to_recordset($1::jsonb) AS h(version int, hash text) WHERE h.version=t.hash_key_version AND h.hash=t.token_hash) AND ($2='' OR c.client_id=$2)
 UNION
 SELECT t.family_id FROM oauth_refresh_tokens t JOIN oauth_clients c ON c.id=t.client_id
 WHERE EXISTS (SELECT 1 FROM jsonb_to_recordset($1::jsonb) AS h(version int, hash text) WHERE h.version=t.hash_key_version AND h.hash=t.token_hash) AND ($2='' OR c.client_id=$2)
 ) AS token_families LIMIT 1`, candidatesJSON, clientID).Scan(&family)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	// Refresh uses the same family lock and never changes family_id, so a rotation
	// between lookup and lock acquisition cannot escape this revocation.
	return r.RevokeFamily(ctx, family, now)
}

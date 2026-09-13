package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"time"
)

// RevokeCredential accepts either credential type. The hint is deliberately not
// used as an authorization decision. An optional external client ID narrows lookup.
// Expired/disabled credentials can still revoke their family.
func (r *oauthServerRepository) RevokeCredential(ctx context.Context, hash, clientID string, now time.Time) error {
	var family uuid.UUID
	err := r.sql.QueryRowContext(ctx, `SELECT family_id FROM (
 SELECT t.family_id FROM oauth_access_tokens t JOIN oauth_clients c ON c.id=t.client_id
 WHERE t.token_hash=$1 AND ($2='' OR c.client_id=$2)
 UNION
 SELECT t.family_id FROM oauth_refresh_tokens t JOIN oauth_clients c ON c.id=t.client_id
 WHERE t.token_hash=$1 AND ($2='' OR c.client_id=$2)
 ) AS token_families LIMIT 1`, hash, clientID).Scan(&family)
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

package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ResumeAuthorizationTransaction atomically binds the authenticated web user to a
// transaction that is still waiting for login.
//
// A single SQL transaction locks the transaction row (FOR UPDATE) and verifies,
// in one serializable read, that:
//   - the transaction is in 'pending_login' (a fresh, unbound authorization);
//   - it has not expired;
//   - it is still unbound (user_id IS NULL) so a second user cannot hijack it;
//   - the request's oauth_browser cookie hashes to the stored browser_session_hash,
//     preventing resume from a different browser than the one that started it;
//   - the OAuth client is active;
//   - the authenticated user is active and not deleted.
//
// Only after all checks pass is the row updated to bind user_id and move to
// 'pending_consent'. Any failure returns ErrInvalidGrant so the caller cannot
// distinguish between "expired", "already bound", and "wrong browser".
func (r *oauthServerRepository) ResumeAuthorizationTransaction(ctx context.Context, in service.OAuthResumeRepoInput) error {
	if in.TransactionID == "" || in.UserID <= 0 {
		return service.ErrInvalidRequest
	}
	tx, err := r.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var (
		status    string
		expiresAt sql.NullTime
		userID    sql.NullInt64
		browser   string
		clientID  int64
	)
	if err = tx.QueryRowContext(ctx, `
SELECT t.status, t.expires_at, t.user_id, t.browser_session_hash, t.client_id
FROM oauth_authorization_transactions t
WHERE t.transaction_id = $1
FOR UPDATE OF t`,
		in.TransactionID).Scan(&status, &expiresAt, &userID, &browser, &clientID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return service.ErrInvalidGrant
		}
		return err
	}

	if status != "pending_login" {
		return service.ErrInvalidGrant
	}
	if !expiresAt.Valid || !expiresAt.Time.After(in.Now) {
		return service.ErrInvalidGrant
	}
	if userID.Valid {
		// Already bound to a user; do not allow rebinding.
		return service.ErrInvalidGrant
	}
	if browser != service.HashOAuthSecret(in.BrowserSession) {
		return service.ErrInvalidGrant
	}

	// Client must be active.
	var clientActive bool
	if err = tx.QueryRowContext(ctx, `SELECT TRUE FROM oauth_clients WHERE id = $1 AND status = 'active'`, clientID).Scan(&clientActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return service.ErrInvalidGrant
		}
		return err
	}

	// The authenticated web user must be active and not deleted.
	var userActive bool
	if err = tx.QueryRowContext(ctx, `SELECT TRUE FROM users WHERE id = $1 AND status = 'active' AND deleted_at IS NULL`, in.UserID).Scan(&userActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return service.ErrInvalidGrant
		}
		return err
	}

	if _, err = tx.ExecContext(ctx, `UPDATE oauth_authorization_transactions SET user_id = $1, status = 'pending_consent', updated_at = $2 WHERE transaction_id = $3`,
		in.UserID, in.Now, in.TransactionID); err != nil {
		return err
	}

	return tx.Commit()
}

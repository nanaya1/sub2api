package repository

import (
	"context"
	"database/sql"
	"time"
)

func (r *oauthServerRepository) AttachAuthorizationTransactionUser(ctx context.Context, id string, userID int64, now time.Time) error {
	tx, e := r.sql.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var status string
	var exp time.Time
	var existing sql.NullInt64
	if e = tx.QueryRowContext(ctx, "SELECT status, expires_at, user_id FROM oauth_authorization_transactions WHERE transaction_id = $1 FOR UPDATE", id).Scan(&status, &exp, &existing); e != nil {
		return e
	}
	if status != "pending_login" || existing.Valid || !exp.After(now) {
		return sql.ErrNoRows
	}
	if _, e = tx.ExecContext(ctx, "UPDATE oauth_authorization_transactions SET user_id = $1, status = $2 WHERE transaction_id = $3", userID, "pending_consent", id); e != nil {
		return e
	}
	return tx.Commit()
}

package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// DecideAuthorizationTransaction atomically closes an authorization transaction.
//
// The transaction row is locked with FOR UPDATE, then the following are verified in
// a single read:
//   - the transaction is in 'pending_consent' and not yet consumed;
//   - it has not expired;
//   - the authenticated user (from the web session, supplied as in.UserID) equals
//     the transaction's bound user, and that user is active and not deleted;
//   - the OAuth client is active, requires PKCE, and allows the authorization_code
//     grant, the requested scopes, and the registered redirect URI;
//   - the browser session hash and the submitted CSRF token hash match.
//
// On approve the same transaction upserts the consent row, inserts the
// authorization code hash, and marks the transaction consumed. On deny a terminal
// 'denied' state is persisted. All writes share one SQL transaction so a failure
// at any step rolls everything back; the plaintext code is returned by the service
// only after this method commits successfully.
func (r *oauthServerRepository) DecideAuthorizationTransaction(ctx context.Context, in service.OAuthDecisionRepoInput) (*service.OAuthDecisionRepoOutput, error) {
	if in.TransactionID == "" || in.UserID <= 0 || (in.Decision != "approve" && in.Decision != "deny") {
		return nil, service.ErrInvalidRequest
	}
	if in.Decision == "approve" && (in.CodeHash == "" || in.CodeTTL <= 0) {
		return nil, service.ErrServerError
	}
	tx, err := r.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var (
		id        int64
		clientID  int64
		redirect  string
		state     string
		challenge string
		method    string
		scopes    []byte
	)
	err = tx.QueryRowContext(ctx, `
SELECT t.id, t.client_id, t.redirect_uri, t.state, t.code_challenge, t.code_challenge_method, t.requested_scopes
FROM oauth_authorization_transactions t
JOIN oauth_clients cl ON cl.id = t.client_id
JOIN users u ON u.id = t.user_id
WHERE t.transaction_id = $1
  AND t.user_id = $2
  AND t.status = 'pending_consent'
  AND t.consumed_at IS NULL
  AND t.expires_at > $3
  AND u.status = 'active' AND u.deleted_at IS NULL
  AND cl.status = 'active' AND cl.client_type = 'public' AND cl.require_pkce = TRUE
  AND cl.allowed_grant_types @> '["authorization_code"]'::jsonb
  AND cl.allowed_scopes @> t.requested_scopes
  AND cl.redirect_uris ? t.redirect_uri
  AND t.browser_session_hash = $4
  AND t.csrf_token_hash = $5
FOR UPDATE OF t, cl, u`,
		in.TransactionID, in.UserID, in.Now, service.HashOAuthSecret(in.BrowserSession), service.HashOAuthSecret(in.CSRFToken)).
		Scan(&id, &clientID, &redirect, &state, &challenge, &method, &scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, service.ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}

	out := &service.OAuthDecisionRepoOutput{RedirectURI: redirect, State: state}

	if in.Decision == "approve" {
		codeExpiry := in.Now.Add(in.CodeTTL)
		if _, err = tx.ExecContext(ctx, `
INSERT INTO oauth_consents (user_id, client_id, scopes, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)
ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, revoked_at = NULL, updated_at = EXCLUDED.updated_at`,
			in.UserID, clientID, scopes, in.Now); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `
INSERT INTO oauth_authorization_codes
  (code_hash, redirect_uri, scopes, code_challenge, code_challenge_method, hash_key_version, expires_at, consumed_at, user_id, client_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'S256', 1, $5, NULL, $6, $7, $8, $8)`,
			in.CodeHash, redirect, scopes, challenge, codeExpiry, in.UserID, clientID, in.Now); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_authorization_transactions SET status = 'approved', consumed_at = $1, updated_at = $1 WHERE id = $2`, in.Now, id); err != nil {
			return nil, err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE oauth_authorization_transactions SET status = 'denied', consumed_at = $1, updated_at = $1 WHERE id = $2`, in.Now, id); err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

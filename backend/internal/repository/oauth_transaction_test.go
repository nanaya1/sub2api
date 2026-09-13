package repository

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOAuthTransactionRepositoryLoad(t *testing.T) {
	db, m, e := sqlmock.New()
	require.NoError(t, e)
	defer db.Close()
	now := time.Now()
	id := uuid.NewString()
	m.ExpectQuery("SELECT.*oauth_authorization_transactions").WillReturnRows(sqlmock.NewRows([]string{"id", "transaction_id", "redirect_uri", "requested_scopes", "state", "code_challenge", "code_challenge_method", "browser_session_hash", "csrf_token_hash", "user_id", "status", "expires_at", "consumed_at", "client_id"}).AddRow(1, id, "https://app/cb", `["openid"]`, "s", "c", "S256", "b", "x", nil, "pending_login", now.Add(time.Minute), nil, 3))
	r := &oauthServerRepository{sql: db}
	x, e := r.FindAuthorizationTransaction(context.Background(), id)
	require.NoError(t, e)
	require.Equal(t, id, x.TransactionID)
	require.NoError(t, m.ExpectationsWereMet())
}

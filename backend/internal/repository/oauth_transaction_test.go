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
	// 2026-09-14：mock 行与列随 fallback 查询调整——列序对齐新 SQL（transaction_id 在首列，
	// 新增 external_client_id / client_name 两列）。原 mock 行注释保留、暂不删除。
	// m.ExpectQuery("SELECT.*oauth_authorization_transactions").WillReturnRows(sqlmock.NewRows([]string{"id", "transaction_id", "redirect_uri", "requested_scopes", "state", "code_challenge", "code_challenge_method", "browser_session_hash", "csrf_token_hash", "user_id", "status", "expires_at", "consumed_at", "client_id"}).AddRow(1, id, "https://app/cb", `["openid"]`, "s", "c", "S256", "b", "x", nil, "pending_login", now.Add(time.Minute), nil, 3))
	m.ExpectQuery("SELECT.*oauth_authorization_transactions").WillReturnRows(sqlmock.NewRows([]string{"transaction_id", "redirect_uri", "requested_scopes", "state", "code_challenge", "code_challenge_method", "browser_session_hash", "csrf_token_hash", "user_id", "status", "expires_at", "consumed_at", "client_id", "external_client_id", "client_name"}).AddRow(id, "https://app/cb", `["openid"]`, "s", "c", "S256", "b", "x", nil, "pending_login", now.Add(time.Minute), nil, 3, "ext-client-id", "MeacoWork"))
	r := &oauthServerRepository{sql: db}
	x, e := r.FindAuthorizationTransaction(context.Background(), id)
	require.NoError(t, e)
	require.Equal(t, id, x.TransactionID)
	// 2026-09-14：新增断言（内部 FK / 对外 client_id / 应用名）。
	require.Equal(t, int64(3), x.ClientInternalID)
	require.Equal(t, "ext-client-id", x.ClientExternalID)
	require.Equal(t, "MeacoWork", x.ClientName)
	require.NoError(t, m.ExpectationsWereMet())
}

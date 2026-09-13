package repository

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAttachOAuthTransactionUserAtomic(t *testing.T) {
	db, m, e := sqlmock.New()
	require.NoError(t, e)
	defer db.Close()
	now := time.Now()
	m.ExpectBegin()
	m.ExpectQuery("SELECT.*FOR UPDATE").WithArgs("tx").WillReturnRows(sqlmock.NewRows([]string{"status", "expires_at", "user_id"}).AddRow("pending_login", now.Add(time.Minute), nil))
	m.ExpectExec("UPDATE oauth_authorization_transactions").WithArgs(int64(7), "pending_consent", "tx").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	r := &oauthServerRepository{sql: db}
	require.NoError(t, r.AttachAuthorizationTransactionUser(context.Background(), "tx", 7, now))
	require.NoError(t, m.ExpectationsWereMet())
}

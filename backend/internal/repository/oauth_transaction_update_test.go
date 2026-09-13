package repository

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func decisionRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "requested_scopes"}).
		AddRow(1, int64(3), "https://app/cb", "state", "challenge", "S256", `["openid","profile"]`)
}

func TestOAuthDecisionApproveAtomic(t *testing.T) {
	db, m, e := sqlmock.New()
	require.NoError(t, e)
	defer db.Close()
	now := time.Now()
	m.ExpectBegin()
	m.ExpectQuery("FROM oauth_authorization_transactions t").WillReturnRows(decisionRows())
	m.ExpectExec("INSERT INTO oauth_consents").WillReturnResult(sqlmock.NewResult(1, 1))
	m.ExpectExec("INSERT INTO oauth_authorization_codes").WillReturnResult(sqlmock.NewResult(1, 1))
	m.ExpectExec("UPDATE oauth_authorization_transactions SET status = 'approved'").WillReturnResult(sqlmock.NewResult(1, 1))
	m.ExpectCommit()
	r := &oauthServerRepository{sql: db}
	out, err := r.DecideAuthorizationTransaction(context.Background(), service.OAuthDecisionRepoInput{
		TransactionID: "tx", UserID: 7, Decision: "approve",
		BrowserSession: "browser", CSRFToken: "csrf",
		CodeHash: service.HashOAuthSecret("code"), CodeTTL: time.Minute, Now: now,
	})
	require.NoError(t, err)
	require.Equal(t, "https://app/cb", out.RedirectURI)
	require.Equal(t, "state", out.State)
	require.NoError(t, m.ExpectationsWereMet())
}

func TestOAuthDecisionDenyPersistsTerminalState(t *testing.T) {
	db, m, e := sqlmock.New()
	require.NoError(t, e)
	defer db.Close()
	now := time.Now()
	m.ExpectBegin()
	m.ExpectQuery("FROM oauth_authorization_transactions t").WillReturnRows(decisionRows())
	m.ExpectExec("UPDATE oauth_authorization_transactions SET status = 'denied'").WillReturnResult(sqlmock.NewResult(1, 1))
	m.ExpectCommit()
	r := &oauthServerRepository{sql: db}
	out, err := r.DecideAuthorizationTransaction(context.Background(), service.OAuthDecisionRepoInput{
		TransactionID: "tx", UserID: 7, Decision: "deny",
		BrowserSession: "browser", CSRFToken: "csrf", Now: now,
	})
	require.NoError(t, err)
	require.Equal(t, "https://app/cb", out.RedirectURI)
	require.Equal(t, "state", out.State)
	require.NoError(t, m.ExpectationsWereMet())
}

// replay and any failed pre-condition (wrong user, wrong browser, wrong csrf)
// all resolve to the SELECT returning no rows, which must yield ErrInvalidGrant
// and roll back without inserting a code or consuming the transaction.
func TestOAuthDecisionReplayAndBadContexts(t *testing.T) {
	cases := []struct {
		name    string
		userID  int64
		browser string
		csrf    string
		replay  bool
	}{
		{"replay: already consumed", 7, "browser", "csrf", true},
		{"wrong user", 8, "browser", "csrf", false},
		{"wrong browser", 7, "evil", "csrf", false},
		{"wrong csrf", 7, "browser", "evil", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, m, e := sqlmock.New()
			require.NoError(t, e)
			defer db.Close()
			now := time.Now()
			// A replayed/already-consumed or mismatched transaction returns no row
			// from the locked SELECT, so the decision cannot proceed.
			m.ExpectBegin()
			m.ExpectQuery("FROM oauth_authorization_transactions t").WillReturnRows(
				sqlmock.NewRows([]string{"id", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "requested_scopes"}))
			m.ExpectRollback()
			r := &oauthServerRepository{sql: db}
			_, err := r.DecideAuthorizationTransaction(context.Background(), service.OAuthDecisionRepoInput{
				TransactionID: "tx", UserID: tc.userID, Decision: "approve",
				BrowserSession: tc.browser, CSRFToken: tc.csrf,
				CodeHash: service.HashOAuthSecret("code"), CodeTTL: time.Minute, Now: now,
			})
			require.ErrorIs(t, err, service.ErrInvalidGrant)
			require.NoError(t, m.ExpectationsWereMet())
		})
	}
}

func TestOAuthDecisionRollbackOnInsertFailure(t *testing.T) {
	db, m, e := sqlmock.New()
	require.NoError(t, e)
	defer db.Close()
	now := time.Now()
	m.ExpectBegin()
	m.ExpectQuery("FROM oauth_authorization_transactions t").WillReturnRows(decisionRows())
	m.ExpectExec("INSERT INTO oauth_consents").WillReturnError(errors.New("disk full"))
	m.ExpectRollback()
	r := &oauthServerRepository{sql: db}
	_, err := r.DecideAuthorizationTransaction(context.Background(), service.OAuthDecisionRepoInput{
		TransactionID: "tx", UserID: 7, Decision: "approve",
		BrowserSession: "browser", CSRFToken: "csrf",
		CodeHash: service.HashOAuthSecret("code"), CodeTTL: time.Minute, Now: now,
	})
	require.Error(t, err)
	require.NoError(t, m.ExpectationsWereMet())
}

func TestOAuthDecisionRejectsInvalidInput(t *testing.T) {
	db, _, e := sqlmock.New()
	require.NoError(t, e)
	defer db.Close()
	r := &oauthServerRepository{sql: db}
	now := time.Now()
	cases := []service.OAuthDecisionRepoInput{
		{TransactionID: "", UserID: 7, Decision: "approve", CodeHash: "h", CodeTTL: time.Minute, Now: now},
		{TransactionID: "tx", UserID: 0, Decision: "approve", CodeHash: "h", CodeTTL: time.Minute, Now: now},
		{TransactionID: "tx", UserID: 7, Decision: "maybe", CodeHash: "h", CodeTTL: time.Minute, Now: now},
		{TransactionID: "tx", UserID: 7, Decision: "approve", CodeTTL: time.Minute, Now: now},
	}
	wants := []error{service.ErrInvalidRequest, service.ErrInvalidRequest, service.ErrInvalidRequest, service.ErrServerError}
	for i, in := range cases {
		_, err := r.DecideAuthorizationTransaction(context.Background(), in)
		require.ErrorIs(t, err, wants[i])
	}
}

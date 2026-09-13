package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestOAuthExchangeCodeCommitsTokensAtomically(t *testing.T) {
	for _, failInsert := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "insert failure rolls back code"}[failInsert], func(t *testing.T) {
			db, m, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			now := time.Now().UTC()
			verifier := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
			m.ExpectBegin()
			m.ExpectQuery("SELECT c.id").WithArgs("code-hash", "desktop").WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "scopes", "expires_at", "consumed_at"}).AddRow(1, 2, 3, "meacowork://oauth/callback", service.HashOAuthSecret(verifier), "S256", []byte(`["profile","offline_access"]`), now.Add(time.Minute), nil))
			m.ExpectExec("UPDATE oauth_authorization_codes").WithArgs(now, int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
			access := m.ExpectExec("INSERT INTO oauth_access_tokens")
			if failInsert {
				access.WillReturnError(errors.New("write failed"))
				m.ExpectRollback()
			} else {
				access.WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectExec("INSERT INTO oauth_refresh_tokens").WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectCommit()
			}
			r := &oauthServerRepository{sql: db}
			_, err = r.ExchangeCode(context.Background(), service.OAuthCodeExchange{CodeHash: "code-hash", ClientID: "desktop", RedirectURI: "meacowork://oauth/callback", Verifier: verifier, AccessHash: "access-hash", RefreshHash: "refresh-hash", Now: now, AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour, IdleTTL: 168 * time.Hour})
			if failInsert {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, m.ExpectationsWereMet())
		})
	}
}

package repository

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOAuthRefreshRotation(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotation inherits deadline", true: "reuse commits revocation"}[reuse], func(t *testing.T) {
			db, m, e := sqlmock.New()
			require.NoError(t, e)
			defer db.Close()
			now := time.Now().UTC()
			deadline := now.Add(5 * time.Minute)
			family := uuid.New()
			m.ExpectBegin()
			m.ExpectQuery("SELECT t.family_id").WithArgs("old", "desktop").WillReturnRows(sqlmock.NewRows([]string{"family_id"}).AddRow(family))
			m.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("oauth-family:" + family.String()).WillReturnResult(sqlmock.NewResult(0, 1))
			var replacement interface{}
			if reuse {
				replacement = int64(99)
			}
			m.ExpectQuery("SELECT t.id").WithArgs("old", "desktop").WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "client_id", "scopes", "expires_at", "idle_expires_at", "revoked_at", "replaced_by_token_id", "last_used_at"}).AddRow(1, 2, 3, `["profile","offline_access"]`, deadline, deadline, nil, replacement, nil))
			if reuse {
				m.ExpectExec("UPDATE oauth_refresh_tokens SET revoked_at").WillReturnResult(sqlmock.NewResult(0, 2))
				m.ExpectExec("UPDATE oauth_access_tokens SET revoked_at").WillReturnResult(sqlmock.NewResult(0, 2))
			} else {
				m.ExpectExec("INSERT INTO oauth_access_tokens").WithArgs("access", family, int64(2), int64(3), `["profile","offline_access"]`, now, deadline).WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectQuery("INSERT INTO oauth_refresh_tokens").WithArgs("refresh", family, int64(2), int64(3), `["profile","offline_access"]`, now, deadline, deadline, int64(1)).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(10))
				m.ExpectExec("UPDATE oauth_refresh_tokens SET last_used_at").WithArgs(now, int64(10), int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			m.ExpectCommit()
			r := &oauthServerRepository{sql: db}
			grant, err := r.RotateRefresh(context.Background(), service.OAuthRefreshExchange{TokenHash: "old", ClientID: "desktop", AccessHash: "access", RefreshHash: "refresh", Now: now, AccessTTL: 15 * time.Minute, IdleTTL: 7 * 24 * time.Hour})
			if reuse {
				require.ErrorIs(t, err, service.ErrInvalidGrant)
				require.Nil(t, grant)
			} else {
				require.NoError(t, err)
				require.Equal(t, deadline, grant.RefreshExpiresAt)
				require.Equal(t, deadline, grant.AccessExpiresAt)
			}
			require.NoError(t, m.ExpectationsWereMet())
		})
	}
}

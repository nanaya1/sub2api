package repository

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOAuthRevokeCredential(t *testing.T) {
	for _, tc := range []struct {
		name, client   string
		found, dbError bool
	}{
		{"legacy access without client", "", true, false},
		{"refresh with client", "desktop", true, false},
		{"unknown or mismatched client", "other", false, false},
		{"lookup failure", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, m, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			family := uuid.New()
			now := time.Now().UTC()
			q := m.ExpectQuery("SELECT family_id FROM").WithArgs("hashed", tc.client)
			if tc.dbError {
				q.WillReturnError(errors.New("offline"))
			} else {
				rows := sqlmock.NewRows([]string{"family_id"})
				if tc.found {
					rows.AddRow(family)
				}
				q.WillReturnRows(rows)
			}
			if tc.found {
				m.ExpectBegin()
				m.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("oauth-family:" + family.String()).WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectExec("UPDATE oauth_refresh_tokens").WithArgs(now, family).WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectExec("UPDATE oauth_access_tokens").WithArgs(now, family).WillReturnResult(sqlmock.NewResult(0, 1))
				m.ExpectCommit()
			}
			r := &oauthServerRepository{sql: db}
			err = r.RevokeCredential(context.Background(), "hashed", tc.client, now)
			if tc.dbError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, m.ExpectationsWereMet())
		})
	}
}

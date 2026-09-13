package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestOAuthRevokeFamilyAtomic(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit both token types", true: "rollback on access update failure"}[fail], func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			r := &oauthServerRepository{sql: db}
			family := uuid.New()
			now := time.Now().UTC()
			mock.ExpectBegin()
			mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("oauth-family:" + family.String()).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("UPDATE oauth_refresh_tokens").WithArgs(now, family).WillReturnResult(sqlmock.NewResult(0, 2))
			update := mock.ExpectExec("UPDATE oauth_access_tokens").WithArgs(now, family)
			if fail {
				update.WillReturnError(errors.New("database unavailable"))
				mock.ExpectRollback()
			} else {
				update.WillReturnResult(sqlmock.NewResult(0, 3))
				mock.ExpectCommit()
			}
			err = r.RevokeFamily(context.Background(), family, now)
			if fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

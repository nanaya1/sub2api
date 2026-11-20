package repository

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestApplyMigrationsFS_PortalLineEndingCompatibility(t *testing.T) {
	const name = "243_cowork_portal_operations.sql"
	const lfChecksum = "94b311209d3afcdf6d20f69f63d47bcb47bc67332893483cfde973f3034603bf"
	const crlfChecksum = "6937c1b81c2f5ae04ffd0ff5b1678da244d3859a47049208675b62572ddb0073"

	content, err := migrations.FS.ReadFile(name)
	require.NoError(t, err)
	lfContent := strings.ReplaceAll(string(content), "\r\n", "\n")
	crlfContent := strings.ReplaceAll(lfContent, "\n", "\r\n")
	// 从真实嵌入文件复现生产日志中的两个摘要，避免将实际 SQL 变更误判为换行差异。
	require.Equal(t, lfChecksum, migrationChecksum(lfContent))
	require.Equal(t, crlfChecksum, migrationChecksum(crlfContent))
	require.False(t, isMigrationChecksumCompatible("244_other.sql", crlfChecksum, lfChecksum))

	for _, tc := range []struct {
		name       string
		dbChecksum string
		content    string
		wantError  bool
	}{
		{name: "crlf_database_lf_build", dbChecksum: crlfChecksum, content: lfContent},
		{name: "lf_database_crlf_build", dbChecksum: lfChecksum, content: crlfContent},
		{name: "lf_database_lf_build", dbChecksum: lfChecksum, content: lfContent},
		{name: "crlf_database_crlf_build", dbChecksum: crlfChecksum, content: crlfContent},
		{name: "unknown_database_checksum_rejected", dbChecksum: strings.Repeat("0", 64), content: lfContent, wantError: true},
		{name: "changed_sql_rejected", dbChecksum: crlfChecksum, content: strings.Replace(lfContent, "VARCHAR(100)", "VARCHAR(101)", 1), wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()

			prepareMigrationsBootstrapExpectations(mock)
			mock.ExpectQuery("SELECT checksum FROM schema_migrations WHERE filename = \\$1").
				WithArgs(name).
				WillReturnRows(sqlmock.NewRows([]string{"checksum"}).AddRow(tc.dbChecksum))
			mock.ExpectExec("SELECT pg_advisory_unlock\\(\\$1\\)").
				WithArgs(migrationsAdvisoryLockID).
				WillReturnResult(sqlmock.NewResult(0, 1))

			// 已应用迁移只允许校验并跳过；重放建表或修改历史校验和都会使 mock 校验失败。
			fsys := fstest.MapFS{name: &fstest.MapFile{Data: []byte(tc.content)}}
			err = applyMigrationsFS(context.Background(), db, fsys)
			if tc.wantError {
				require.ErrorContains(t, err, "checksum mismatch")
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

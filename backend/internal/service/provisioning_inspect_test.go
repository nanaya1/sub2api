//go:build unit

package service

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// TestProvisioningInspect 验证读取真实数据及额外授权，不用映射状态代替实体状态
func TestProvisioningInspect(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	svc := NewProvisioningService(db, nil, nil)
	mock.ExpectBegin()
	mock.ExpectQuery("FROM provisioning_user_bindings").WithArgs("cowork", "7").WillReturnRows(
		sqlmock.NewRows([]string{"id", "version", "groups_version", "binding_status", "exists", "deleted", "name", "status", "restricted"}).
			AddRow(10, 100, 200, "active", true, false, "actual-name", "disabled", false))
	mock.ExpectQuery("FROM user_allowed_groups").WithArgs(int64(10), "cowork", 4001).WillReturnRows(
		sqlmock.NewRows([]string{"tenant", "external", "managed"}).AddRow("1", "11", true).AddRow("", "", false))
	mock.ExpectQuery("FROM provisioning_group_bindings").WithArgs("cowork", "1", "11").WillReturnRows(
		sqlmock.NewRows([]string{"id", "version", "binding_status", "exists", "deleted", "name", "description", "status", "restricted"}).
			AddRow(20, 300, "active", true, true, "deleted-group", "", "active", true))
	mock.ExpectCommit()
	result, err := svc.Inspect(context.Background(), ProvisioningInspectInput{Source: "cowork", Objects: []ProvisioningInspectObject{
		{ObjectType: "user", ExternalID: "7"}, {ObjectType: "group", ExternalID: "11", TenantKey: "1"},
	}})
	require.NoError(t, err)
	require.Equal(t, "actual-name", result.Items[0].Name)
	require.Equal(t, "disabled", result.Items[0].Status)
	require.False(t, result.Items[0].Restricted)
	require.Len(t, result.Items[0].Groups, 1)
	require.Equal(t, 1, result.Items[0].UnmanagedGroups)
	require.True(t, result.Items[1].Deleted)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisioningInspectMissingAndInvalid(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	svc := NewProvisioningService(db, nil, nil)
	object := ProvisioningInspectObject{ObjectType: "user", ExternalID: "7"}
	for _, input := range []ProvisioningInspectInput{
		{}, {Source: "cowork"}, {Source: "cowork", Objects: []ProvisioningInspectObject{object, object}},
		{Source: "cowork", Objects: []ProvisioningInspectObject{{ObjectType: "user", ExternalID: "7", TenantKey: "1"}}},
		{Source: "cowork", Objects: []ProvisioningInspectObject{{ObjectType: "group", ExternalID: "7"}}},
	} {
		_, err := svc.Inspect(context.Background(), input)
		require.ErrorIs(t, err, ErrProvisioningInvalidRequest)
	}
	mock.ExpectBegin()
	mock.ExpectQuery("FROM provisioning_user_bindings").WithArgs("cowork", "7").WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	result, err := svc.Inspect(context.Background(), ProvisioningInspectInput{Source: "cowork", Objects: []ProvisioningInspectObject{object}})
	require.NoError(t, err)
	require.False(t, result.Items[0].BindingFound)
	require.NotNil(t, result.Items[0].Groups)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProvisioningInspectRejectsTruncatedAuthorization(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("FROM provisioning_user_bindings").WillReturnRows(
		sqlmock.NewRows([]string{"id", "version", "groups_version", "binding_status", "exists", "deleted", "name", "status", "restricted"}).
			AddRow(10, 100, 200, "active", true, false, "name", "active", true))
	rows := sqlmock.NewRows([]string{"tenant", "external", "managed"})
	for i := 0; i < 4001; i++ {
		rows.AddRow("", "", false)
	}
	mock.ExpectQuery("FROM user_allowed_groups").WillReturnRows(rows)
	mock.ExpectRollback()
	result, err := NewProvisioningService(db, nil, nil).Inspect(context.Background(), ProvisioningInspectInput{
		Source: "cowork", Objects: []ProvisioningInspectObject{{ObjectType: "user", ExternalID: "7"}},
	})
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrProvisioningInvalidRequest)
	require.NoError(t, mock.ExpectationsWereMet())
}

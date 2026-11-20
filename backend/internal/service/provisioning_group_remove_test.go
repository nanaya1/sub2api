//go:build unit

package service

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"testing"
)

type provisioningRemovalAdminStub struct {
	AdminService
	calls int
}

func (s *provisioningRemovalAdminStub) DeleteGroup(context.Context, int64) error {
	s.calls++
	return nil
}

// 旧事件没有授权上限，拒绝后不得写数据库或删除管理员真实模型组。
func TestProvisioningRemoveGroupRejectsLegacy(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	admin := &provisioningRemovalAdminStub{}
	_, err = NewProvisioningService(db, admin, nil).RemoveGroup(context.Background(), "cowork", "1", "3", 100)
	require.ErrorIs(t, err, ErrProvisioningInvalidRequest)
	require.Zero(t, admin.calls)
	require.NoError(t, mock.ExpectationsWereMet())
}
func TestProvisioningModelGroupPolicyRequiresExplicitSnapshot(t *testing.T) {
	for _, input := range []ProvisioningGroupUpsertInput{
		{Source: "cowork", TenantKey: "1", ExternalGroupID: "3", Status: "active", Version: 1},
		{Source: "cowork", TenantKey: "1", ExternalGroupID: "3", Status: "active", Version: 1, ModelGroupIDs: []int64{}, TenantGroupIDs: []int64{1, 1}, TenantStatus: "active"},
	} {
		_, err := NewProvisioningService(nil, nil, nil).UpsertGroup(context.Background(), input)
		require.ErrorIs(t, err, ErrProvisioningInvalidRequest)
	}
}

//go:build unit

package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

// provisioningRemovalAdminStub 只替代正式删除入口，其余管理能力不参与投影测试
type provisioningRemovalAdminStub struct {
	AdminService
	calls int
	err   error
}

func (s *provisioningRemovalAdminStub) DeleteGroup(_ context.Context, id int64) error {
	if id != 20 {
		return errors.New("unexpected local group")
	}
	s.calls++
	return s.err
}

// TestProvisioningRemoveGroup 验证正式删除、重复确认、乱序和部分提交失败的重试边界
func TestProvisioningRemoveGroup(t *testing.T) {
	controlledError := errors.New("controlled failure")
	for _, tc := range []struct {
		name            string
		status          string
		metadataVersion int64
		membersVersion  int64
		missing         bool
		adminErr        error
		updateErr       error
		commitErr       error
		wantErr         bool
		wantCalls       int
	}{
		{name: "active", status: "active", wantCalls: 1},
		{name: "disabled", status: "disabled", wantCalls: 1},
		{name: "already_deleted", status: "deleted"},
		{name: "never_provisioned", missing: true},
		{name: "stale_metadata", status: "active", metadataVersion: 200},
		{name: "stale_members", status: "active", membersVersion: 200},
		{name: "prior_delete_committed", status: "active", adminErr: ErrGroupNotFound, wantCalls: 1},
		{name: "admin_failed", status: "active", adminErr: controlledError, wantErr: true, wantCalls: 1},
		{name: "mapping_failed", status: "active", updateErr: controlledError, wantErr: true, wantCalls: 1},
		{name: "commit_unknown", status: "active", commitErr: controlledError, wantErr: true, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			admin := &provisioningRemovalAdminStub{err: tc.adminErr}
			svc := NewProvisioningService(db, admin)
			mock.ExpectBegin()
			mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("cowork/1/group/3").WillReturnResult(sqlmock.NewResult(0, 1))
			rows := sqlmock.NewRows([]string{"local_group_id", "version", "members_version", "status"})
			if !tc.missing {
				rows.AddRow(int64(20), tc.metadataVersion, tc.membersVersion, tc.status)
			}
			mock.ExpectQuery("FROM provisioning_group_bindings").WithArgs("cowork", "1", "3").WillReturnRows(rows)
			stale := tc.metadataVersion > 100 || tc.membersVersion > 100
			adminFailed := tc.adminErr != nil && !errors.Is(tc.adminErr, ErrGroupNotFound)
			if tc.missing {
				// 无本地分组时只写墓碑，不创建业务分组或按名称认领
				mock.ExpectExec("INSERT INTO provisioning_group_bindings").WithArgs("cowork", "1", "3", int64(100)).WillReturnResult(sqlmock.NewResult(0, 1))
			} else if !stale && !adminFailed {
				update := mock.ExpectExec("UPDATE provisioning_group_bindings").WithArgs("cowork", "1", "3", int64(100))
				if tc.updateErr != nil {
					update.WillReturnError(tc.updateErr)
				} else {
					update.WillReturnResult(sqlmock.NewResult(0, 1))
				}
			}
			if adminFailed || tc.updateErr != nil {
				mock.ExpectRollback()
			} else if tc.commitErr != nil {
				mock.ExpectCommit().WillReturnError(tc.commitErr)
			} else {
				mock.ExpectCommit()
			}
			result, err := svc.RemoveGroup(context.Background(), "cowork", "1", "3", 100)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, "3", result.ExternalGroupID)
				if stale {
					require.Equal(t, tc.status, result.Status)
				} else {
					require.Equal(t, "deleted", result.Status)
					require.Equal(t, int64(100), result.Version)
				}
				if tc.missing {
					require.Zero(t, result.LocalGroupID)
				}
			}
			require.Equal(t, tc.wantCalls, admin.calls)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestProvisioningDeletedGroupCannotRevive 验证删除标记同时阻断延迟新增、停用和成员替换
func TestProvisioningDeletedGroupCannotRevive(t *testing.T) {
	for _, localID := range []int64{0, 20} {
		for _, operation := range []string{"upsert", "disable", "members"} {
			t.Run(fmt.Sprintf("%s/local_id_%d", operation, localID), func(t *testing.T) {
				db, mock, err := sqlmock.New()
				require.NoError(t, err)
				defer db.Close()
				svc := NewProvisioningService(db, nil)
				mock.ExpectBegin()
				key := "cowork/1/group/3"
				if operation == "members" {
					key += "/members"
				}
				mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(key).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery("FROM provisioning_group_bindings").WithArgs("cowork", "1", "3").WillReturnRows(
					sqlmock.NewRows([]string{"local_group_id", "version", "members_version", "status"}).AddRow(localID, int64(100), int64(50), "deleted"))
				// 只允许读取和提交；任何恢复分组或成员的SQL都会使期望失败
				mock.ExpectCommit()
				var result *ProvisioningGroupResult
				switch operation {
				case "upsert":
					result, err = svc.UpsertGroup(context.Background(), ProvisioningGroupUpsertInput{Source: "cowork", TenantKey: "1", ExternalGroupID: "3", Name: "研发", Version: 200})
				case "disable":
					result, err = svc.DisableGroup(context.Background(), "cowork", "1", "3", 200)
				case "members":
					result, err = svc.ReplaceGroupMembers(context.Background(), ProvisioningGroupMembersInput{Source: "cowork", TenantKey: "1", ExternalGroupID: "3", ExternalUserIDs: []string{"2"}, Version: 200})
				}
				require.NoError(t, err)
				require.Equal(t, "deleted", result.Status)
				require.Equal(t, localID, result.LocalGroupID)
				require.Equal(t, int64(100), result.Version)
				require.NoError(t, mock.ExpectationsWereMet())
			})
		}
	}
}

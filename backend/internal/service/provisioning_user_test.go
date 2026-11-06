//go:build unit

package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

type provisioningUserAdminStub struct {
	AdminService
	calls int
	err   error
}

func (s *provisioningUserAdminStub) DeleteUser(_ context.Context, id int64) error {
	if id != 10 {
		return errors.New("unexpected local user")
	}
	s.calls++
	return s.err
}

func expectGlobalUser(mock sqlmock.Sqlmock, id, version, groupsVersion int64, status string) {
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("cowork/user/7").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM provisioning_user_bindings").WithArgs("cowork", "7").WillReturnRows(
		sqlmock.NewRows([]string{"local_user_id", "version", "groups_version", "status"}).AddRow(id, version, groupsVersion, status))
}

// TestProvisioningUserGroups 验证跨企业授权原子替换、空集合、缺失依赖及乱序重放
func TestProvisioningUserGroups(t *testing.T) {
	for _, scenario := range []string{"two_tenants", "empty", "missing_group", "deleted_group", "stale", "duplicate", "deleted_user"} {
		t.Run(scenario, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			svc := NewProvisioningService(db, nil, nil)
			version := int64(200)
			status := "disabled" // 全局禁用账号仍保存分组归属
			if scenario == "deleted_user" {
				status = "deleted"
			}
			expectGlobalUser(mock, 10, 100, 150, status)
			input := ProvisioningUserGroupsInput{Source: "cowork", ExternalUserID: "7", Version: version, Groups: []ProvisioningGroupReference{}}
			if scenario == "stale" {
				input.Version = 149
			}
			if scenario == "duplicate" {
				input.Version = 150
			}
			skip := scenario == "stale" || scenario == "duplicate" || scenario == "deleted_user"
			if !skip && scenario != "empty" {
				input.Groups = []ProvisioningGroupReference{{TenantKey: "2", ExternalGroupID: "4"}, {TenantKey: "1", ExternalGroupID: "3"}}
				query := mock.ExpectQuery("FROM provisioning_group_bindings").WithArgs("cowork", "1", "3")
				if scenario == "missing_group" {
					query.WillReturnError(sql.ErrNoRows)
				} else {
					groupStatus := "active"
					if scenario == "deleted_group" {
						groupStatus = "deleted"
					}
					query.WillReturnRows(sqlmock.NewRows([]string{"local_group_id", "status"}).AddRow(20, groupStatus))
					mock.ExpectQuery("FROM provisioning_group_bindings").WithArgs("cowork", "2", "4").WillReturnRows(
						sqlmock.NewRows([]string{"local_group_id", "status"}).AddRow(30, "active"))
				}
			}
			if !skip && scenario != "missing_group" {
				mock.ExpectExec("UPDATE users SET restrict_public_groups").WithArgs(int64(10)).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("DELETE FROM user_allowed_groups WHERE user_id").WithArgs(int64(10)).WillReturnResult(sqlmock.NewResult(0, 3))
				if scenario != "empty" {
					if scenario != "deleted_group" {
						mock.ExpectExec("INSERT INTO user_allowed_groups").WithArgs(int64(10), int64(20)).WillReturnResult(sqlmock.NewResult(0, 1))
					}
					mock.ExpectExec("INSERT INTO user_allowed_groups").WithArgs(int64(10), int64(30)).WillReturnResult(sqlmock.NewResult(0, 1))
				}
				mock.ExpectExec("UPDATE provisioning_user_bindings SET groups_version").WithArgs("cowork", "7", version).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			if scenario == "missing_group" {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			result, err := svc.ReplaceUserGroups(context.Background(), input)
			if scenario == "missing_group" {
				require.ErrorIs(t, err, ErrProvisioningBindingNotFound)
			} else {
				require.NoError(t, err)
				if skip {
					require.Equal(t, int64(150), result.GroupsVersion)
				} else {
					require.Equal(t, version, result.GroupsVersion)
				}
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestProvisioningGlobalUserRemoval 验证正式删除、删除先到、失败重试和墓碑确认
func TestProvisioningGlobalUserRemoval(t *testing.T) {
	for _, scenario := range []string{"active", "missing", "deleted", "already_removed", "failed", "stale"} {
		t.Run(scenario, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			admin := &provisioningUserAdminStub{}
			if scenario == "already_removed" {
				admin.err = ErrUserNotFound
			}
			if scenario == "failed" {
				admin.err = errors.New("controlled failure")
			}
			svc := NewProvisioningService(db, admin, nil)
			status := "active"
			if scenario == "deleted" {
				status = "deleted"
			}
			if scenario == "missing" {
				mock.ExpectBegin()
				mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("cowork/user/7").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery("FROM provisioning_user_bindings").WithArgs("cowork", "7").WillReturnError(sql.ErrNoRows)
				mock.ExpectExec("INSERT INTO provisioning_user_bindings").WithArgs("cowork", "7", int64(200)).WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				version := int64(100)
				if scenario == "stale" {
					version = 300
				}
				expectGlobalUser(mock, 10, version, 150, status)
				if scenario != "stale" && scenario != "failed" {
					mock.ExpectExec("DELETE FROM user_allowed_groups").WithArgs(int64(10)).WillReturnResult(sqlmock.NewResult(0, 2))
					mock.ExpectExec("UPDATE provisioning_user_bindings SET version").WithArgs("cowork", "7", int64(200)).WillReturnResult(sqlmock.NewResult(0, 1))
				}
			}
			if scenario == "failed" {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			result, err := svc.RemoveUser(context.Background(), "cowork", "7", 200)
			if scenario == "failed" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if scenario != "stale" {
					require.Equal(t, "deleted", result.Status)
				}
			}
			wantCalls := 1
			if scenario == "missing" || scenario == "deleted" || scenario == "stale" {
				wantCalls = 0
			}
			require.Equal(t, wantCalls, admin.calls)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestProvisioningUserTombstoneBlocksUpsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	expectGlobalUser(mock, 0, 100, 0, "deleted")
	mock.ExpectCommit()
	result, err := NewProvisioningService(db, nil, nil).UpsertUser(context.Background(), ProvisioningUserUpsertInput{Source: "cowork", ExternalUserID: "7", Username: "user", Version: 200})
	require.NoError(t, err)
	require.Equal(t, "deleted", result.Status)
	require.Zero(t, result.LocalUserID)
	require.NoError(t, mock.ExpectationsWereMet())
}

// 提交成功后必须立即撤销已有Key缓存；提交失败不得报告同步成功
type provisioningCacheStub struct {
	APIKeyAuthCacheInvalidator
	users []int64
}

func (s *provisioningCacheStub) InvalidateAuthCacheByUserID(_ context.Context, id int64) {
	s.users = append(s.users, id)
}

func TestProvisioningGlobalUserUpsert(t *testing.T) {
	for _, scenario := range []string{"new", "update", "stale", "duplicate", "commit_failed"} {
		t.Run(scenario, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			cache := &provisioningCacheStub{}
			svc := NewProvisioningService(db, nil, cache)
			input := ProvisioningUserUpsertInput{Source: "cowork", ExternalUserID: "7", Username: "updated", Status: "disabled", Version: 200}
			if scenario == "new" {
				mock.ExpectBegin()
				mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("cowork/user/7").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery("FROM provisioning_user_bindings").WithArgs("cowork", "7").WillReturnError(sql.ErrNoRows)
				mock.ExpectQuery("INSERT INTO users .*TRUE.*RETURNING id").WithArgs(provisioningUserEmail(input), sqlmock.AnyArg(), "disabled", "updated").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(10))
				mock.ExpectExec("INSERT INTO provisioning_user_bindings").WithArgs("cowork", "7", int64(10), int64(200), "disabled").WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				if scenario == "stale" {
					input.Version = 99
				}
				if scenario == "duplicate" {
					input.Version = 100
				}
				expectGlobalUser(mock, 10, 100, 150, "active")
				if scenario != "stale" && scenario != "duplicate" {
					mock.ExpectExec("UPDATE users SET email").WithArgs(int64(10), provisioningUserEmail(input), "updated", "disabled").WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectExec("UPDATE provisioning_user_bindings SET version").WithArgs("cowork", "7", int64(200), "disabled").WillReturnResult(sqlmock.NewResult(0, 1))
				}
			}
			if scenario == "commit_failed" {
				mock.ExpectCommit().WillReturnError(errors.New("unknown commit"))
			} else {
				mock.ExpectCommit()
			}
			result, err := svc.UpsertUser(context.Background(), input)
			if scenario == "commit_failed" {
				require.Error(t, err)
				require.Empty(t, cache.users)
			} else {
				require.NoError(t, err)
				require.Equal(t, int64(10), result.LocalUserID)
				require.Equal(t, []int64{10}, cache.users)
				if scenario == "stale" || scenario == "duplicate" {
					require.Equal(t, "active", result.Status)
				} else {
					require.Equal(t, "disabled", result.Status)
				}
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestProvisioningGroupsMustBeExplicit(t *testing.T) {
	_, err := NewProvisioningService(nil, nil, nil).ReplaceUserGroups(context.Background(), ProvisioningUserGroupsInput{Source: "cowork", ExternalUserID: "7", Version: 1})
	require.ErrorIs(t, err, ErrProvisioningInvalidRequest)
}

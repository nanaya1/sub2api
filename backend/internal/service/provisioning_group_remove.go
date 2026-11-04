package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// RemoveGroup 按可信外部映射执行正式分组删除，保留历史映射以确认重复请求
func (s *ProvisioningService) RemoveGroup(ctx context.Context, source, tenantKey, externalGroupID string, version int64) (*ProvisioningGroupResult, error) {
	if err := validateProvisioningKey(source, tenantKey, externalGroupID); err != nil {
		return nil, err
	}
	if version < 0 || s == nil || s.db == nil {
		return nil, ErrProvisioningInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin provisioning group removal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 与元数据同步使用同一个外部身份锁，并锁定映射行以串行化成员替换
	if err := lockProvisioningKey(ctx, tx, source+"/"+tenantKey+"/group/"+externalGroupID); err != nil {
		return nil, err
	}
	result := &ProvisioningGroupResult{Source: source, TenantKey: tenantKey, ExternalGroupID: externalGroupID, Version: version, Status: "deleted"}
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(local_group_id, 0), version, members_version, status
		FROM provisioning_group_bindings
		WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3
		FOR UPDATE`, source, tenantKey, externalGroupID).
		Scan(&result.LocalGroupID, &result.Version, &result.MembersVersion, &result.Status)
	if errors.Is(err, sql.ErrNoRows) {
		// 删除可能先于首次投影到达；保留不含本地分组的墓碑，阻止在途旧新增请求复活
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO provisioning_group_bindings
			(source, tenant_key, external_group_id, local_group_id, version, status)
			VALUES ($1, $2, $3, NULL, $4, 'deleted')`, source, tenantKey, externalGroupID, version); err != nil {
			return nil, fmt.Errorf("save provisioning group tombstone: %w", err)
		}
		return result, commitProvisioningTx(tx, result)
	}
	if err != nil {
		return nil, fmt.Errorf("load provisioning group removal: %w", err)
	}
	if version < result.Version || version < result.MembersVersion {
		return result, commitProvisioningTx(tx, result)
	}
	if result.Status != "deleted" {
		if s.adminService == nil {
			return nil, errors.New("provisioning group deletion is unavailable")
		}
		// 复用管理端删除：清理成员、渠道、订阅、组合路由并软删除分组，提交后失效相关缓存
		// 正式删除使用独立事务；映射提交失败后的重试允许通过分组已不存在确认先前删除
		if err := s.adminService.DeleteGroup(ctx, result.LocalGroupID); err != nil && !errors.Is(err, ErrGroupNotFound) {
			return nil, fmt.Errorf("remove provisioning group: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE provisioning_group_bindings
		SET version = $4, status = 'deleted', updated_at = NOW()
		WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3`, source, tenantKey, externalGroupID, version); err != nil {
		return nil, fmt.Errorf("save provisioning group removal: %w", err)
	}
	result.Version = version
	result.Status = "deleted"
	return result, commitProvisioningTx(tx, result)
}

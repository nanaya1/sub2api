package service

import "context"

// RemoveGroup 旧分组写协议已停用，明确拒绝历史调用，避免误删管理员维护的真实模型组。
// 新方案由cowork本地收敛业务组授权与SK，不创建下游业务组墓碑。
func (s *ProvisioningService) RemoveGroup(ctx context.Context, source, tenantKey, externalGroupID string, version int64) (*ProvisioningGroupResult, error) {
	return nil, ErrProvisioningInvalidRequest
}

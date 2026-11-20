package service

import (
	"context"
	"sort"
	"strings"

	"github.com/lib/pq"
)

// PortalClientKeyIDs 只读核对Java已筛选的Key，未入选项不读取明文；完整处理，禁止静默截断。
func (s *ProvisioningService) PortalClientKeyIDs(ctx context.Context, identity CoworkPortalIdentity) ([]int64, error) {
	if identity.TenantKey == "" || validateCoworkIDs(identity.APIKeyIDs, 100) != nil {
		return nil, ErrPortalInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT k.id FROM api_keys k
		JOIN users u ON u.id=k.user_id
		JOIN groups g ON g.id=k.group_id
		JOIN user_allowed_groups a ON a.user_id=u.id AND a.group_id=g.id
		WHERE k.user_id=$1 AND k.id=ANY($2::bigint[]) AND k.deleted_at IS NULL
		  AND k.status='active' AND (k.expires_at IS NULL OR k.expires_at>NOW())
		  AND (k.quota<=0 OR k.quota_used<k.quota)
		  AND u.status='active' AND u.deleted_at IS NULL AND u.restrict_public_groups=TRUE
		  AND g.status='active' AND g.deleted_at IS NULL AND g.platform!='composite'
		  AND g.subscription_type='standard' ORDER BY k.id`, identity.UserID, pq.Array(identity.APIKeyIDs))
	if err != nil {
		return nil, ErrPortalUnavailable
	}
	defer rows.Close()
	result := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil {
			return nil, ErrPortalUnavailable
		}
		result = append(result, id)
	}
	if rows.Err() != nil {
		return nil, ErrPortalUnavailable
	}
	return result, nil
}

// DiscoverCoworkModels 实时读取可调度账号，使用正式账号模型准入过滤候选目录。
// 通配映射只能筛选具体模型，不能把通配符当作模型ID下发；仓储失败整份失败。
func (s *GatewayService) DiscoverCoworkModels(ctx context.Context, groupID int64, platform string, candidates []string) ([]string, error) {
	accounts, err := s.accountRepo.ListSchedulableByGroupID(ctx, groupID)
	if err != nil {
		return nil, ErrPortalUnavailable
	}
	concrete := map[string]bool{}
	add := func(model string) {
		if strings.TrimSpace(model) != "" && !strings.ContainsAny(model, "*?#\r\n") {
			concrete[model] = true
		}
	}
	for _, model := range candidates {
		add(model)
	}
	eligible := make([]Account, 0, len(accounts))
	for _, account := range accounts {
		if account.Platform != platform {
			continue
		}
		eligible = append(eligible, account)
		for model := range account.GetModelMapping() {
			add(model)
		}
	}
	result := []string{}
	for model := range concrete {
		for _, account := range eligible {
			if account.IsModelSupported(model) {
				result = append(result, model)
				break
			}
		}
	}
	if len(result) > 4000 {
		return nil, ErrPortalUnavailable
	}
	sort.Strings(result)
	return result, nil
}

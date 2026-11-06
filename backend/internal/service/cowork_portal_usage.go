package service

import (
	"context"
	"fmt"
	"time"
)

// CoworkPortalUsageFilter 对历史用量使用企业投影归属，换组或组删除不改变统计口径。
type CoworkPortalUsageFilter struct {
	Start    time.Time
	End      time.Time
	Model    string
	APIKeyID int64
	Page     int
	PageSize int
}

// PortalUsage 查询只读企业投影，所有身份条件在分页和聚合前进入SQL。
func (s *ProvisioningService) PortalUsage(ctx context.Context, identity CoworkPortalIdentity, filter CoworkPortalUsageFilter, operation string) (any, error) {
	if identity.TenantKey == "" || filter.Page < 1 || filter.PageSize < 1 || filter.PageSize > 100 || !filter.Start.Before(filter.End) || filter.End.Sub(filter.Start) > 367*24*time.Hour {
		return nil, ErrPortalInvalid
	}
	where := ` FROM usage_logs l WHERE l.user_id = $1 AND l.created_at >= $2 AND l.created_at < $3
        AND EXISTS (SELECT 1 FROM provisioning_group_bindings b WHERE b.local_group_id = l.group_id AND b.source = $4 AND b.tenant_key = $5)`
	args := []any{identity.UserID, filter.Start, filter.End, identity.Source, identity.TenantKey}
	if filter.Model != "" {
		args = append(args, filter.Model)
		where += fmt.Sprintf(" AND COALESCE(NULLIF(l.requested_model, ''), l.model) = $%d", len(args))
	}
	if filter.APIKeyID > 0 {
		args = append(args, filter.APIKeyID)
		where += fmt.Sprintf(" AND l.api_key_id = $%d", len(args))
	}
	if operation == "usage.summary" {
		var requests, input, output, creation, read int64
		var cost, actual float64
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(l.input_tokens),0), COALESCE(SUM(l.output_tokens),0), COALESCE(SUM(l.cache_creation_tokens),0), COALESCE(SUM(l.cache_read_tokens),0), COALESCE(SUM(l.total_cost),0), COALESCE(SUM(l.actual_cost),0)`+where, args...).Scan(&requests, &input, &output, &creation, &read, &cost, &actual)
		if err != nil {
			return nil, ErrPortalUnavailable
		}
		return map[string]any{"requests": requests, "inputTokens": input, "outputTokens": output, "cacheCreationTokens": creation, "cacheReadTokens": read, "cost": cost, "actualCost": actual}, nil
	}
	result := []map[string]any{}
	if operation == "usage.trend" {
		rows, err := s.db.QueryContext(ctx, `SELECT to_char(l.created_at AT TIME ZONE 'Asia/Shanghai', 'YYYY-MM-DD'), COUNT(*), COALESCE(SUM(l.input_tokens+l.output_tokens+l.cache_creation_tokens+l.cache_read_tokens),0), COALESCE(SUM(l.actual_cost),0)`+where+` GROUP BY 1 ORDER BY 1`, args...)
		if err != nil {
			return nil, ErrPortalUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var date string
			var requests, tokens int64
			var actual float64
			if rows.Scan(&date, &requests, &tokens, &actual) != nil {
				return nil, ErrPortalUnavailable
			}
			result = append(result, map[string]any{"date": date, "requests": requests, "tokens": tokens, "actualCost": actual})
		}
		if rows.Err() != nil {
			return nil, ErrPortalUnavailable
		}
		return result, nil
	}
	if operation != "usage.page" {
		return nil, ErrPortalInvalid
	}
	var total int64
	if s.db.QueryRowContext(ctx, `SELECT COUNT(*)`+where, args...).Scan(&total) != nil {
		return nil, ErrPortalUnavailable
	}
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := s.db.QueryContext(ctx, `SELECT l.id,l.api_key_id,COALESCE(NULLIF(l.requested_model,''),l.model),l.input_tokens,l.output_tokens,l.cache_creation_tokens,l.cache_read_tokens,l.total_cost,l.actual_cost,l.created_at`+where+fmt.Sprintf(" ORDER BY l.created_at DESC,l.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, ErrPortalUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var id, key, input, output, creation, read int64
		var model string
		var cost, actual float64
		var created time.Time
		if rows.Scan(&id, &key, &model, &input, &output, &creation, &read, &cost, &actual, &created) != nil {
			return nil, ErrPortalUnavailable
		}
		result = append(result, map[string]any{"id": id, "apiKeyId": key, "model": model, "inputTokens": input, "outputTokens": output, "cacheCreationTokens": creation, "cacheReadTokens": read, "cost": cost, "actualCost": actual, "createTime": created})
	}
	if rows.Err() != nil {
		return nil, ErrPortalUnavailable
	}
	return CoworkPortalPage(result, total, filter.Page, filter.PageSize), nil
}

// PortalKeyIDs 先在数据库限定本人和企业后分页，绝不分页后过滤。
func (s *ProvisioningService) PortalKeyIDs(ctx context.Context, identity CoworkPortalIdentity, page, size int, keyword, status string) ([]int64, int64, error) {
	if identity.TenantKey == "" || page < 1 || size < 1 || size > 100 {
		return nil, 0, ErrPortalInvalid
	}
	where := ` FROM api_keys k WHERE k.user_id=$1 AND k.deleted_at IS NULL
        AND EXISTS(SELECT 1 FROM provisioning_group_bindings b WHERE b.local_group_id=k.group_id AND b.source=$2 AND b.tenant_key=$3)`
	args := []any{identity.UserID, identity.Source, identity.TenantKey}
	if keyword != "" {
		args = append(args, keyword)
		where += fmt.Sprintf(" AND strpos(lower(k.name),lower($%d))>0", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND k.status=$%d", len(args))
	}
	var total int64
	if s.db.QueryRowContext(ctx, `SELECT COUNT(*)`+where, args...).Scan(&total) != nil {
		return nil, 0, ErrPortalUnavailable
	}
	args = append(args, size, (page-1)*size)
	rows, err := s.db.QueryContext(ctx, `SELECT k.id`+where+fmt.Sprintf(" ORDER BY k.created_at DESC,k.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, ErrPortalUnavailable
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) != nil {
			return nil, 0, ErrPortalUnavailable
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil {
		return nil, 0, ErrPortalUnavailable
	}
	return ids, total, nil
}

// CoworkPortalPage 保持主系统分页字段，不返回原始实体。
func CoworkPortalPage(items any, total int64, page, size int) map[string]any {
	return map[string]any{"items": items, "total": total, "current": page, "size": size, "pages": (total + int64(size) - 1) / int64(size)}
}

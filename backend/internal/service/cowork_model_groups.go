package service

import (
	"context"

	"github.com/lib/pq"
)

type CoworkModelGroup struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Status   string `json:"status"`
}

func (s *ProvisioningService) ModelGroupCatalog(ctx context.Context, page, size int) (any, error) {
	if page < 1 || size < 1 || size > 100 || page > 100000 {
		return nil, ErrPortalInvalid
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups WHERE deleted_at IS NULL AND platform!='composite' AND subscription_type='standard'`).Scan(&total); err != nil {
		return nil, ErrPortalUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,platform,status FROM groups WHERE deleted_at IS NULL AND platform!='composite' AND subscription_type='standard' ORDER BY id LIMIT $1 OFFSET $2`, size, (page-1)*size)
	if err != nil {
		return nil, ErrPortalUnavailable
	}
	defer rows.Close()
	result := []CoworkModelGroup{}
	for rows.Next() {
		var item CoworkModelGroup
		if rows.Scan(&item.ID, &item.Name, &item.Platform, &item.Status) != nil {
			return nil, ErrPortalUnavailable
		}
		result = append(result, item)
	}
	if rows.Err() != nil {
		return nil, ErrPortalUnavailable
	}
	return CoworkPortalPage(result, total, page, size), nil
}

// validateCoworkIDs 对内部服务提交的完整ID范围整体校验，不截断或默认扩大范围。
func validateCoworkIDs(ids []int64, max int) error {
	if ids == nil || len(ids) > max {
		return ErrPortalInvalid
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return ErrPortalInvalid
		}
		seen[id] = true
	}
	return nil
}

func (s *ProvisioningService) PortalModelGroups(ctx context.Context, identity CoworkPortalIdentity, ids []int64) ([]CoworkModelGroup, error) {
	if err := validateCoworkIDs(ids, 100); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT g.id,g.name,g.platform,g.status FROM groups g JOIN user_allowed_groups u ON u.group_id=g.id
        WHERE u.user_id=$1 AND g.id=ANY($2::bigint[]) AND g.status='active' AND g.deleted_at IS NULL AND g.platform!='composite' AND g.subscription_type='standard' ORDER BY g.id`, identity.UserID, pq.Array(ids))
	if err != nil {
		return nil, ErrPortalUnavailable
	}
	defer rows.Close()
	result := []CoworkModelGroup{}
	for rows.Next() {
		var group CoworkModelGroup
		if err := rows.Scan(&group.ID, &group.Name, &group.Platform, &group.Status); err != nil {
			return nil, ErrPortalUnavailable
		}
		result = append(result, group)
	}
	return result, rows.Err()
}

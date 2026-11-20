package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ProvisioningInspectObject 仅接收可信外部身份，不按名称或邮箱认领实体
type ProvisioningInspectObject struct {
	ObjectType string `json:"object_type"`
	ExternalID string `json:"external_id"`
	TenantKey  string `json:"tenant_key"`
}

type ProvisioningInspectInput struct {
	Source  string                      `json:"source"`
	Objects []ProvisioningInspectObject `json:"objects"`
}

// ProvisioningInspectItem 返回实际实体及授权的安全投影，不包含邮箱、密码、Key或Token
type ProvisioningInspectItem struct {
	ProvisioningInspectObject
	ModelGroupIDs       []int64                      `json:"model_group_ids"`
	TenantGroupIDs      []int64                      `json:"tenant_group_ids"`
	TenantPolicyVersion int64                        `json:"tenant_policy_version"`
	TenantStatus        string                       `json:"tenant_status"`
	BindingFound        bool                         `json:"binding_found"`
	LocalID             int64                        `json:"local_id"`
	Version             int64                        `json:"version"`
	GroupsVersion       int64                        `json:"groups_version"`
	BindingStatus       string                       `json:"binding_status"`
	EntityExists        bool                         `json:"entity_exists"`
	Deleted             bool                         `json:"deleted"`
	Name                string                       `json:"name"`
	Description         string                       `json:"description"`
	Status              string                       `json:"status"`
	Restricted          bool                         `json:"restricted"`
	Groups              []ProvisioningGroupReference `json:"groups"`
	UnmanagedGroups     int                          `json:"unmanaged_groups"`
}

type ProvisioningInspectResult struct {
	Source string                    `json:"source"`
	Items  []ProvisioningInspectItem `json:"items"`
}

func validateProvisioningInspect(input ProvisioningInspectInput) error {
	if strings.TrimSpace(input.Source) == "" || len(input.Source) > 100 || len(input.Objects) == 0 || len(input.Objects) > 100 {
		return ErrProvisioningInvalidRequest
	}
	seen := map[ProvisioningInspectObject]bool{}
	for _, object := range input.Objects {
		if strings.TrimSpace(object.ExternalID) == "" || len(object.ExternalID) > 200 || seen[object] {
			return ErrProvisioningInvalidRequest
		}
		if object.ObjectType == "user" {
			if object.TenantKey != "" {
				return ErrProvisioningInvalidRequest
			}
		} else if object.ObjectType != "group" || strings.TrimSpace(object.TenantKey) == "" || len(object.TenantKey) > 100 {
			return ErrProvisioningInvalidRequest
		}
		seen[object] = true
	}
	return nil
}

// Inspect 在单个只读快照中读取映射与实际数据，整个请求最多读取4000条授权
func (s *ProvisioningService) Inspect(ctx context.Context, input ProvisioningInspectInput) (*ProvisioningInspectResult, error) {
	if err := validateProvisioningInspect(input); err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("provisioning inspection unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	result := &ProvisioningInspectResult{Source: input.Source, Items: make([]ProvisioningInspectItem, 0, len(input.Objects))}
	budget := 4000
	for _, object := range input.Objects {
		item := ProvisioningInspectItem{ProvisioningInspectObject: object, Groups: []ProvisioningGroupReference{}, ModelGroupIDs: []int64{}}
		if object.ObjectType == "user" {
			err = tx.QueryRowContext(ctx, `SELECT COALESCE(b.local_user_id,0),b.version,b.groups_version,b.status,
			 u.id IS NOT NULL,COALESCE(u.deleted_at IS NOT NULL,FALSE),COALESCE(u.username,''),COALESCE(u.status,''),COALESCE(u.restrict_public_groups,FALSE)
			 FROM provisioning_user_bindings b LEFT JOIN users u ON u.id=b.local_user_id
			 WHERE b.source=$1 AND b.external_user_id=$2`, input.Source, object.ExternalID).
				Scan(&item.LocalID, &item.Version, &item.GroupsVersion, &item.BindingStatus, &item.EntityExists, &item.Deleted, &item.Name, &item.Status, &item.Restricted)
		} else {
			// 业务组仅在 cowork 保存，不再存在下游映射实体。
			err = sql.ErrNoRows
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		item.BindingFound = err == nil
		if item.BindingFound && object.ObjectType == "user" && item.LocalID > 0 {
			if err := inspectProvisioningGroups(ctx, tx, input.Source, &item, &budget); err != nil {
				return nil, err
			}
		}
		result.Items = append(result.Items, item)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func inspectProvisioningGroups(ctx context.Context, tx *sql.Tx, source string, item *ProvisioningInspectItem, budget *int) error {
	// 返回正式授权完整集合；企业及业务组归属由 cowork 核对，不在下游复制。
	item.ModelGroupIDs = []int64{}
	rows, err := tx.QueryContext(ctx, "SELECT group_id FROM user_allowed_groups WHERE user_id=$1 ORDER BY group_id LIMIT $2", item.LocalID, *budget+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		*budget--
		if *budget < 0 {
			return ErrProvisioningInvalidRequest
		}
		item.ModelGroupIDs = append(item.ModelGroupIDs, id)
	}
	return rows.Err()
}

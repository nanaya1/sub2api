package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrProvisioningInvalidRequest  = errors.New("invalid provisioning request")
	ErrProvisioningBindingNotFound = errors.New("provisioning binding not found")
	ErrProvisioningStaleVersion    = errors.New("provisioning version is stale")
)

// ProvisioningService 负责外部用户/分组投影的幂等落库。
// 业务数据仍由主服务维护，当前平台只保存本地投影和外部 ID 映射。
type ProvisioningService struct {
	db                   *sql.DB
	adminService         AdminService
	authCacheInvalidator APIKeyAuthCacheInvalidator
}

func NewProvisioningService(db *sql.DB, adminService AdminService, invalidator APIKeyAuthCacheInvalidator) *ProvisioningService {
	return &ProvisioningService{db: db, adminService: adminService, authCacheInvalidator: invalidator}
}

type ProvisioningGroupUpsertInput struct {
	Source          string
	TenantKey       string
	ExternalGroupID string
	Name            string
	Description     string
	Status          string
	Version         int64
}

type ProvisioningGroupResult struct {
	Source          string `json:"source"`
	TenantKey       string `json:"tenant_key"`
	ExternalGroupID string `json:"external_group_id"`
	LocalGroupID    int64  `json:"local_group_id"`
	Version         int64  `json:"version"`
	MembersVersion  int64  `json:"members_version"`
	Status          string `json:"status"`
}

func (s *ProvisioningService) UpsertGroup(ctx context.Context, input ProvisioningGroupUpsertInput) (*ProvisioningGroupResult, error) {
	if err := validateProvisioningKey(input.Source, input.TenantKey, input.ExternalGroupID); err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("provisioning database is unavailable")
	}
	status := normalizeProvisioningStatus(input.Status)
	if input.Version < 0 {
		return nil, ErrProvisioningInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin provisioning group transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProvisioningKey(ctx, tx, input.Source+"/"+input.TenantKey+"/group/"+input.ExternalGroupID); err != nil {
		return nil, err
	}

	result := &ProvisioningGroupResult{Source: input.Source, TenantKey: input.TenantKey, ExternalGroupID: input.ExternalGroupID, Status: status}
	var existingStatus string
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(local_group_id, 0), version, members_version, status
		FROM provisioning_group_bindings
		WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3
		FOR UPDATE`, input.Source, input.TenantKey, input.ExternalGroupID).
		Scan(&result.LocalGroupID, &result.Version, &result.MembersVersion, &existingStatus)
	if errors.Is(err, sql.ErrNoRows) {
		result.LocalGroupID, err = createProvisioningGroup(ctx, tx, input, status)
		if err != nil {
			return nil, err
		}
		result.Version = input.Version
		_, err = tx.ExecContext(ctx, `
			INSERT INTO provisioning_group_bindings
			(source, tenant_key, external_group_id, local_group_id, version, status)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			input.Source, input.TenantKey, input.ExternalGroupID, result.LocalGroupID, result.Version, status)
		if err != nil {
			return nil, fmt.Errorf("insert provisioning group binding: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("load provisioning group binding: %w", err)
	} else if existingStatus == "deleted" {
		// 已删除外部身份永久保留映射，延迟或重放的新增事件不能复活历史分组
		result.Status = existingStatus
	} else if input.Version >= result.Version {
		if err := updateProvisioningGroup(ctx, tx, result.LocalGroupID, input, status); err != nil {
			return nil, err
		}
		result.Version = input.Version
		if _, err := tx.ExecContext(ctx, `
			UPDATE provisioning_group_bindings
			SET version = $4, status = $5, updated_at = NOW()
			WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3`,
			input.Source, input.TenantKey, input.ExternalGroupID, result.Version, status); err != nil {
			return nil, fmt.Errorf("update provisioning group binding: %w", err)
		}
	} else {
		result.Status = existingStatus
	}
	return result, commitProvisioningTx(tx, result)
}

func (s *ProvisioningService) DisableGroup(ctx context.Context, source, tenantKey, externalGroupID string, version int64) (*ProvisioningGroupResult, error) {
	return s.UpsertGroup(ctx, ProvisioningGroupUpsertInput{Source: source, TenantKey: tenantKey, ExternalGroupID: externalGroupID, Name: externalGroupID, Status: "disabled", Version: version})
}

func validateProvisioningKey(source, tenantKey, externalID string) error {
	if strings.TrimSpace(source) == "" || strings.TrimSpace(tenantKey) == "" || strings.TrimSpace(externalID) == "" {
		return ErrProvisioningInvalidRequest
	}
	if len(source) > 100 || len(tenantKey) > 200 || len(externalID) > 200 {
		return ErrProvisioningInvalidRequest
	}
	return nil
}

func normalizeProvisioningStatus(status string) string {
	if strings.EqualFold(strings.TrimSpace(status), "disabled") {
		return "disabled"
	}
	return "active"
}

func lockProvisioningKey(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}

func createProvisioningGroup(ctx context.Context, tx *sql.Tx, input ProvisioningGroupUpsertInput, status string) (int64, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = input.ExternalGroupID
	}
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO groups (name, description, platform, status, subscription_type, is_exclusive) VALUES ($1, $2, 'anthropic', $3, 'standard', TRUE) RETURNING id`, name, strings.TrimSpace(input.Description), status).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create provisioning group: %w", err)
	}
	return id, nil
}

func updateProvisioningGroup(ctx context.Context, tx *sql.Tx, localGroupID int64, input ProvisioningGroupUpsertInput, status string) error {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = input.ExternalGroupID
	}
	if _, err := tx.ExecContext(ctx, `UPDATE groups SET name = $2, description = $3, status = $4, is_exclusive = TRUE, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, localGroupID, name, strings.TrimSpace(input.Description), status); err != nil {
		return fmt.Errorf("update provisioning group: %w", err)
	}
	return nil
}

func commitProvisioningTx(tx *sql.Tx, result any) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit provisioning transaction: %w", err)
	}
	return nil
}

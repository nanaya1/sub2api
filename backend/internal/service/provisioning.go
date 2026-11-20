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
	Source              string
	TenantKey           string
	ExternalGroupID     string
	Name                string
	Description         string
	Status              string
	Version             int64
	ModelGroupIDs       []int64
	TenantGroupIDs      []int64
	TenantPolicyVersion int64
	TenantStatus        string
}

type ProvisioningGroupResult struct {
	PolicyID        int64  `json:"policy_id"`
	Source          string `json:"source"`
	TenantKey       string `json:"tenant_key"`
	ExternalGroupID string `json:"external_group_id"`
	Version         int64  `json:"version"`
	Status          string `json:"status"`
}

func (s *ProvisioningService) UpsertGroup(ctx context.Context, input ProvisioningGroupUpsertInput) (*ProvisioningGroupResult, error) {
	return nil, ErrProvisioningInvalidRequest
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

func commitProvisioningTx(tx *sql.Tx, result any) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit provisioning transaction: %w", err)
	}
	return nil
}

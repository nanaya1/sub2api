package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrProvisioningInvalidRequest = errors.New("invalid provisioning request")
	ErrProvisioningBindingNotFound = errors.New("provisioning binding not found")
	ErrProvisioningStaleVersion = errors.New("provisioning version is stale")
)

// ProvisioningService 负责外部用户/分组投影的幂等落库。
// 业务数据仍由主服务维护，当前平台只保存本地投影和外部 ID 映射。
type ProvisioningService struct {
	db           *sql.DB
	adminService AdminService
}

func NewProvisioningService(db *sql.DB, adminService AdminService) *ProvisioningService {
	return &ProvisioningService{db: db, adminService: adminService}
}

type ProvisioningUserUpsertInput struct {
	Source           string
	TenantKey        string
	ExternalUserID   string
	Email            string
	Username         string
	Status           string
	Version          int64
}

type ProvisioningGroupUpsertInput struct {
	Source           string
	TenantKey        string
	ExternalGroupID  string
	Name             string
	Description      string
	Status           string
	Version          int64
}

type ProvisioningGroupMembersInput struct {
	Source           string
	TenantKey        string
	ExternalGroupID  string
	ExternalUserIDs  []string
	Version          int64
}

type ProvisioningUserResult struct {
	Source         string `json:"source"`
	TenantKey      string `json:"tenant_key"`
	ExternalUserID string `json:"external_user_id"`
	LocalUserID    int64  `json:"local_user_id"`
	Version        int64  `json:"version"`
	Status         string `json:"status"`
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

func (s *ProvisioningService) UpsertUser(ctx context.Context, input ProvisioningUserUpsertInput) (*ProvisioningUserResult, error) {
	if err := validateProvisioningKey(input.Source, input.TenantKey, input.ExternalUserID); err != nil {
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
		return nil, fmt.Errorf("begin provisioning user transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProvisioningKey(ctx, tx, input.Source+"/"+input.TenantKey+"/user/"+input.ExternalUserID); err != nil {
		return nil, err
	}

	var result ProvisioningUserResult
	var existingStatus string
	err = tx.QueryRowContext(ctx, `
		SELECT local_user_id, version, status
		FROM provisioning_user_bindings
		WHERE source = $1 AND tenant_key = $2 AND external_user_id = $3
		FOR UPDATE`, input.Source, input.TenantKey, input.ExternalUserID).
		Scan(&result.LocalUserID, &result.Version, &existingStatus)
	if errors.Is(err, sql.ErrNoRows) {
		result.LocalUserID, err = createProvisioningUser(ctx, tx, input, status)
		if err != nil {
			return nil, err
		}
		result.Version = input.Version
		_, err = tx.ExecContext(ctx, `
			INSERT INTO provisioning_user_bindings
			(source, tenant_key, external_user_id, local_user_id, version, status)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			input.Source, input.TenantKey, input.ExternalUserID, result.LocalUserID, result.Version, status)
		if err != nil {
			return nil, fmt.Errorf("insert provisioning user binding: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("load provisioning user binding: %w", err)
	} else {
		if input.Version < result.Version {
			result.Status = existingStatus
			result.Source, result.TenantKey, result.ExternalUserID = input.Source, input.TenantKey, input.ExternalUserID
			return &result, commitProvisioningTx(tx, &result)
		}
		if err := updateProvisioningUser(ctx, tx, result.LocalUserID, input, status); err != nil {
			return nil, err
		}
		result.Version = input.Version
		if _, err := tx.ExecContext(ctx, `
			UPDATE provisioning_user_bindings
			SET version = $4, status = $5, updated_at = NOW()
			WHERE source = $1 AND tenant_key = $2 AND external_user_id = $3`,
			input.Source, input.TenantKey, input.ExternalUserID, result.Version, status); err != nil {
			return nil, fmt.Errorf("update provisioning user binding: %w", err)
		}
	}
	result.Source, result.TenantKey, result.ExternalUserID, result.Status = input.Source, input.TenantKey, input.ExternalUserID, status
	return &result, commitProvisioningTx(tx, &result)
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

func (s *ProvisioningService) DisableUser(ctx context.Context, source, tenantKey, externalUserID string, version int64) (*ProvisioningUserResult, error) {
	return s.UpsertUser(ctx, ProvisioningUserUpsertInput{Source: source, TenantKey: tenantKey, ExternalUserID: externalUserID, Status: "disabled", Version: version})
}

func (s *ProvisioningService) DisableGroup(ctx context.Context, source, tenantKey, externalGroupID string, version int64) (*ProvisioningGroupResult, error) {
	return s.UpsertGroup(ctx, ProvisioningGroupUpsertInput{Source: source, TenantKey: tenantKey, ExternalGroupID: externalGroupID, Name: externalGroupID, Status: "disabled", Version: version})
}

func (s *ProvisioningService) ReplaceGroupMembers(ctx context.Context, input ProvisioningGroupMembersInput) (*ProvisioningGroupResult, error) {
	if err := validateProvisioningKey(input.Source, input.TenantKey, input.ExternalGroupID); err != nil {
		return nil, err
	}
	if input.Version < 0 || s == nil || s.db == nil {
		return nil, ErrProvisioningInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin provisioning membership transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProvisioningKey(ctx, tx, input.Source+"/"+input.TenantKey+"/group/"+input.ExternalGroupID+"/members"); err != nil {
		return nil, err
	}
	var result ProvisioningGroupResult
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(local_group_id, 0), version, members_version, status
		FROM provisioning_group_bindings
		WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3
		FOR UPDATE`, input.Source, input.TenantKey, input.ExternalGroupID).
		Scan(&result.LocalGroupID, &result.Version, &result.MembersVersion, &result.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) { return nil, ErrProvisioningBindingNotFound }
		return nil, fmt.Errorf("load provisioning group for members: %w", err)
	}
	result.Source, result.TenantKey, result.ExternalGroupID = input.Source, input.TenantKey, input.ExternalGroupID
	if result.Status == "deleted" {
		// 删除后的成员事件只确认结果，不恢复成员或渠道授权
		return &result, commitProvisioningTx(tx, &result)
	}
	if input.Version < result.MembersVersion {
		return &result, commitProvisioningTx(tx, &result)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_allowed_groups WHERE group_id = $1`, result.LocalGroupID); err != nil {
		return nil, fmt.Errorf("clear provisioning group members: %w", err)
	}
	for _, externalUserID := range input.ExternalUserIDs {
		var localUserID int64
		if err := tx.QueryRowContext(ctx, `
			SELECT local_user_id FROM provisioning_user_bindings
			WHERE source = $1 AND tenant_key = $2 AND external_user_id = $3`, input.Source, input.TenantKey, externalUserID).Scan(&localUserID); err != nil {
			if errors.Is(err, sql.ErrNoRows) { return nil, fmt.Errorf("user binding %q: %w", externalUserID, ErrProvisioningBindingNotFound) }
			return nil, fmt.Errorf("load provisioning member: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_allowed_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, localUserID, result.LocalGroupID); err != nil {
			return nil, fmt.Errorf("insert provisioning group member: %w", err)
		}
	}
	result.MembersVersion = input.Version
	if _, err := tx.ExecContext(ctx, `UPDATE provisioning_group_bindings SET members_version = $4, updated_at = NOW() WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3`, input.Source, input.TenantKey, input.ExternalGroupID, input.Version); err != nil {
		return nil, fmt.Errorf("update provisioning members version: %w", err)
	}
	return &result, commitProvisioningTx(tx, &result)
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
	if strings.EqualFold(strings.TrimSpace(status), "disabled") { return "disabled" }
	return "active"
}

func lockProvisioningKey(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}

func createProvisioningUser(ctx context.Context, tx *sql.Tx, input ProvisioningUserUpsertInput, status string) (int64, error) {
	email := strings.TrimSpace(input.Email)
	if email == "" { email = fmt.Sprintf("%s@provisioning.invalid", strings.ReplaceAll(input.ExternalUserID, "@", "_")) }
	password := make([]byte, 24)
	if _, err := rand.Read(password); err != nil { return 0, err }
	hash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(password)), bcrypt.DefaultCost)
	if err != nil { return 0, fmt.Errorf("hash provisioning password: %w", err) }
	username := strings.TrimSpace(input.Username)
	if username == "" { username = input.ExternalUserID }
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash, role, status, username, signup_source) VALUES ($1, $2, 'user', $3, $4, 'email') RETURNING id`, email, string(hash), status, username).Scan(&id)
	if err != nil { return 0, fmt.Errorf("create provisioning user: %w", err) }
	return id, nil
}

func updateProvisioningUser(ctx context.Context, tx *sql.Tx, localUserID int64, input ProvisioningUserUpsertInput, status string) error {
	email := strings.TrimSpace(input.Email)
	username := strings.TrimSpace(input.Username)
	if username == "" { username = input.ExternalUserID }
	if _, err := tx.ExecContext(ctx, `UPDATE users SET email = COALESCE(NULLIF($2, ''), email), username = $3, status = $4, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, localUserID, email, username, status); err != nil { return fmt.Errorf("update provisioning user: %w", err) }
	return nil
}

func createProvisioningGroup(ctx context.Context, tx *sql.Tx, input ProvisioningGroupUpsertInput, status string) (int64, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" { name = input.ExternalGroupID }
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO groups (name, description, platform, status, subscription_type) VALUES ($1, $2, 'anthropic', $3, 'standard') RETURNING id`, name, strings.TrimSpace(input.Description), status).Scan(&id)
	if err != nil { return 0, fmt.Errorf("create provisioning group: %w", err) }
	return id, nil
}

func updateProvisioningGroup(ctx context.Context, tx *sql.Tx, localGroupID int64, input ProvisioningGroupUpsertInput, status string) error {
	name := strings.TrimSpace(input.Name)
	if name == "" { name = input.ExternalGroupID }
	if _, err := tx.ExecContext(ctx, `UPDATE groups SET name = $2, description = $3, status = $4, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, localGroupID, name, strings.TrimSpace(input.Description), status); err != nil { return fmt.Errorf("update provisioning group: %w", err) }
	return nil
}

func commitProvisioningTx(tx *sql.Tx, result any) error {
	if err := tx.Commit(); err != nil { return fmt.Errorf("commit provisioning transaction: %w", err) }
	return nil
}

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// ProvisioningUserUpsertInput 只以主系统全局用户标识定位账号
type ProvisioningUserUpsertInput struct {
	Source         string
	ExternalUserID string
	Email          string
	Username       string
	Status         string
	Version        int64
}

type ProvisioningGroupReference struct {
	TenantKey       string `json:"tenant_key"`
	ExternalGroupID string `json:"external_group_id"`
}

type ProvisioningUserGroupsInput struct {
	Source         string
	ExternalUserID string
	Groups         []ProvisioningGroupReference
	Version        int64
}

type ProvisioningUserResult struct {
	Source         string `json:"source"`
	ExternalUserID string `json:"external_user_id"`
	LocalUserID    int64  `json:"local_user_id"`
	Version        int64  `json:"version"`
	GroupsVersion  int64  `json:"groups_version"`
	Status         string `json:"status"`
}

func validateProvisioningUserKey(source, externalID string, version int64) error {
	if strings.TrimSpace(source) == "" || len(source) > 100 || strings.TrimSpace(externalID) == "" || len(externalID) > 200 || version <= 0 {
		return ErrProvisioningInvalidRequest
	}
	return nil
}

func lockProvisioningUser(ctx context.Context, tx *sql.Tx, source, externalID string) error {
	return lockProvisioningKey(ctx, tx, source+"/user/"+externalID)
}

func loadProvisioningUser(ctx context.Context, tx *sql.Tx, source, externalID string) (*ProvisioningUserResult, error) {
	result := &ProvisioningUserResult{Source: source, ExternalUserID: externalID}
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(local_user_id, 0), version, groups_version, status
		FROM provisioning_user_bindings WHERE source = $1 AND external_user_id = $2 FOR UPDATE`, source, externalID).
		Scan(&result.LocalUserID, &result.Version, &result.GroupsVersion, &result.Status)
	return result, err
}

func (s *ProvisioningService) commitUser(ctx context.Context, tx *sql.Tx, result *ProvisioningUserResult) (*ProvisioningUserResult, error) {
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit provisioning user: %w", err)
	}
	// 显式失效缩短权限变更窗口，数据库 Outbox 保证进程在提交后退出时仍可补发
	if s.authCacheInvalidator != nil && result.LocalUserID > 0 {
		s.authCacheInvalidator.InvalidateAuthCacheByUserID(ctx, result.LocalUserID)
	}
	return result, nil
}

func (s *ProvisioningService) UpsertUser(ctx context.Context, input ProvisioningUserUpsertInput) (*ProvisioningUserResult, error) {
	if err := validateProvisioningUserKey(input.Source, input.ExternalUserID, input.Version); err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("provisioning database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProvisioningUser(ctx, tx, input.Source, input.ExternalUserID); err != nil {
		return nil, err
	}
	result, err := loadProvisioningUser(ctx, tx, input.Source, input.ExternalUserID)
	status := normalizeProvisioningStatus(input.Status)
	if errors.Is(err, sql.ErrNoRows) {
		result.LocalUserID, err = createProvisioningUser(ctx, tx, input, status)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO provisioning_user_bindings
			(source, external_user_id, local_user_id, version, status) VALUES ($1, $2, $3, $4, $5)`,
			input.Source, input.ExternalUserID, result.LocalUserID, input.Version, status)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		// 删除墓碑永久阻止同一外部身份复活，相同版本只确认第一次提交的结果
		if result.Status == "deleted" || input.Version <= result.Version {
			return s.commitUser(ctx, tx, result)
		}
		if err := updateProvisioningUser(ctx, tx, result.LocalUserID, input, status); err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE provisioning_user_bindings SET version = $3, status = $4, updated_at = NOW()
			WHERE source = $1 AND external_user_id = $2`, input.Source, input.ExternalUserID, input.Version, status)
		if err != nil {
			return nil, err
		}
	}
	result.Version, result.Status = input.Version, status
	return s.commitUser(ctx, tx, result)
}

// ReplaceUserGroups 原子替换一个全局用户在所有企业中的完整分组授权
func (s *ProvisioningService) ReplaceUserGroups(ctx context.Context, input ProvisioningUserGroupsInput) (*ProvisioningUserResult, error) {
	if err := validateProvisioningUserKey(input.Source, input.ExternalUserID, input.Version); err != nil {
		return nil, err
	}
	if input.Groups == nil {
		return nil, ErrProvisioningInvalidRequest
	}
	groups := append([]ProvisioningGroupReference(nil), input.Groups...)
	for _, group := range groups {
		if err := validateProvisioningKey(input.Source, group.TenantKey, group.ExternalGroupID); err != nil {
			return nil, err
		}
	}
	// 多个并发用户引用相同分组时按稳定顺序锁定映射，避免锁顺序反转
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].TenantKey != groups[j].TenantKey {
			return groups[i].TenantKey < groups[j].TenantKey
		}
		return groups[i].ExternalGroupID < groups[j].ExternalGroupID
	})
	if s == nil || s.db == nil {
		return nil, errors.New("provisioning database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProvisioningUser(ctx, tx, input.Source, input.ExternalUserID); err != nil {
		return nil, err
	}
	result, err := loadProvisioningUser(ctx, tx, input.Source, input.ExternalUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProvisioningBindingNotFound
	}
	if err != nil {
		return nil, err
	}
	if result.Status == "deleted" || input.Version <= result.GroupsVersion {
		return s.commitUser(ctx, tx, result)
	}
	localGroups := make(map[int64]struct{}, len(groups))
	for _, group := range groups {
		var id int64
		var status string
		err := tx.QueryRowContext(ctx, `SELECT COALESCE(local_group_id, 0), status FROM provisioning_group_bindings
			WHERE source = $1 AND tenant_key = $2 AND external_group_id = $3 FOR UPDATE`,
			input.Source, group.TenantKey, group.ExternalGroupID).Scan(&id, &status)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProvisioningBindingNotFound
		}
		if err != nil {
			return nil, err
		}
		// 延迟的完整名单不能重新授予已经正式删除的分组
		if status != "deleted" && id > 0 {
			localGroups[id] = struct{}{}
		}
	}
	// 限制公开组，确保清理掉的人工授权不会因公开组默认可用而继续生效
	updated, err := tx.ExecContext(ctx, `UPDATE users SET restrict_public_groups = TRUE, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`, result.LocalUserID)
	if err != nil {
		return nil, err
	}
	if count, err := updated.RowsAffected(); err != nil || count != 1 {
		return nil, ErrUserNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_allowed_groups WHERE user_id = $1`, result.LocalUserID); err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(localGroups))
	for id := range localGroups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_allowed_groups (user_id, group_id) VALUES ($1, $2)`, result.LocalUserID, id); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE provisioning_user_bindings SET groups_version = $3, updated_at = NOW()
		WHERE source = $1 AND external_user_id = $2`, input.Source, input.ExternalUserID, input.Version); err != nil {
		return nil, err
	}
	result.GroupsVersion = input.Version
	return s.commitUser(ctx, tx, result)
}

// RemoveUser 复用正式用户删除，并保留全局身份墓碑以阻止重放恢复
func (s *ProvisioningService) RemoveUser(ctx context.Context, source, externalID string, version int64) (*ProvisioningUserResult, error) {
	if err := validateProvisioningUserKey(source, externalID, version); err != nil {
		return nil, err
	}
	if s == nil || s.db == nil {
		return nil, errors.New("provisioning database is unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProvisioningUser(ctx, tx, source, externalID); err != nil {
		return nil, err
	}
	result, err := loadProvisioningUser(ctx, tx, source, externalID)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `INSERT INTO provisioning_user_bindings (source, external_user_id, local_user_id, version, status)
			VALUES ($1, $2, NULL, $3, 'deleted')`, source, externalID, version)
	} else if err != nil {
		return nil, err
	} else {
		if version < result.Version || version < result.GroupsVersion {
			return s.commitUser(ctx, tx, result)
		}
		if result.Status != "deleted" {
			if s.adminService == nil {
				return nil, errors.New("provisioning user deletion is unavailable")
			}
			// 正式删除使用独立事务；映射提交失败时，重试允许确认用户已经删除
			if err := s.adminService.DeleteUser(ctx, result.LocalUserID); err != nil && !errors.Is(err, ErrUserNotFound) {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_allowed_groups WHERE user_id = $1`, result.LocalUserID); err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE provisioning_user_bindings SET version = $3, status = 'deleted', updated_at = NOW()
			WHERE source = $1 AND external_user_id = $2`, source, externalID, version)
	}
	if err != nil {
		return nil, err
	}
	result.Version, result.Status = version, "deleted"
	return s.commitUser(ctx, tx, result)
}

func provisioningUserEmail(input ProvisioningUserUpsertInput) string {
	if email := strings.TrimSpace(input.Email); email != "" {
		return email
	}
	name := strings.TrimSpace(input.Username)
	if name == "" {
		name = input.ExternalUserID
	}
	// 保留可读用户名，将邮箱分隔符、空格等替换，避免生成多个 @ 或非法地址。
	name = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r) {
			return unicode.ToLower(r)
		}
		return '-'
	}, name)
	for strings.Contains(name, "..") {
		name = strings.ReplaceAll(name, "..", ".")
	}
	name = truncateProvisioningEmailName(name, 64)
	if name == "" {
		name = "user"
	}
	return name + "@sub2api.local"
}

func truncateProvisioningEmailName(name string, maxBytes int) string {
	if len(name) > maxBytes {
		// 邮箱本地部分最多 64 字节，截断时保留完整中文字符。
		name = name[:maxBytes]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	return strings.Trim(name, ".-_")
}

func resolveProvisioningUserEmail(ctx context.Context, tx *sql.Tx, input ProvisioningUserUpsertInput, localUserID int64) (string, error) {
	email := provisioningUserEmail(input)
	if strings.TrimSpace(input.Email) != "" {
		return email, nil
	}
	digest := sha256.Sum256([]byte(input.Source + "\x00" + input.ExternalUserID))
	name := strings.TrimSuffix(email, "@sub2api.local")
	fallback := truncateProvisioningEmailName(name, 51) + "-" + hex.EncodeToString(digest[:6]) + "@sub2api.local"
	for _, candidate := range []string{email, fallback} {
		// 按候选邮箱串行分配，避免不同外部用户并发同步时选中同一占位地址。
		if err := lockProvisioningKey(ctx, tx, "provisioning/email/"+candidate); err != nil {
			return "", err
		}
		var occupied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users
			WHERE email = $1 AND deleted_at IS NULL AND id <> $2)`, candidate, localUserID).Scan(&occupied); err != nil {
			return "", err
		}
		if !occupied {
			return candidate, nil
		}
	}
	// 已有账号只用于判断地址占用，绝不能按邮箱认领或覆盖其他用户。
	return "", ErrEmailExists
}

func createProvisioningUser(ctx context.Context, tx *sql.Tx, input ProvisioningUserUpsertInput, status string) (int64, error) {
	email, err := resolveProvisioningUserEmail(ctx, tx, input, 0)
	if err != nil {
		return 0, err
	}
	password := make([]byte, 24)
	if _, err := rand.Read(password); err != nil {
		return 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(password)), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	username := strings.TrimSpace(input.Username)
	if username == "" {
		username = input.ExternalUserID
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO users (email, password_hash, role, status, username, signup_source, restrict_public_groups)
		VALUES ($1, $2, 'user', $3, $4, 'email', TRUE) RETURNING id`, email, string(hash), status, username).Scan(&id)
	return id, err
}

func updateProvisioningUser(ctx context.Context, tx *sql.Tx, id int64, input ProvisioningUserUpsertInput, status string) error {
	email, err := resolveProvisioningUserEmail(ctx, tx, input, id)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(input.Username)
	if username == "" {
		username = input.ExternalUserID
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET email = $2, username = $3, status = $4,
		restrict_public_groups = TRUE, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, id, email, username, status)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrUserNotFound
	}
	return nil
}

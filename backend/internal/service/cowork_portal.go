package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var (
	ErrPortalNotReady      = infraerrors.Conflict("PORTAL_NOT_READY", "model projection is not ready")
	ErrPortalNotFound      = infraerrors.NotFound("PORTAL_NOT_FOUND", "resource not found")
	ErrPortalInvalid       = infraerrors.BadRequest("PORTAL_INVALID_ARGUMENT", "invalid portal request")
	ErrPortalConflict      = infraerrors.Conflict("PORTAL_REQUEST_CONFLICT", "operation id has different content")
	ErrPortalUnconfirmed   = infraerrors.Conflict("PORTAL_UNCONFIRMED", "operation result is unconfirmed")
	ErrPortalUnavailable   = infraerrors.ServiceUnavailable("PORTAL_UNAVAILABLE", "model service unavailable")
	ErrPortalRejected      = infraerrors.BadRequest("PORTAL_REJECTED", "operation rejected")
	portalRequestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// CoworkPortalIdentity 只允许由独立服务凭据认证后解析外部稳定身份。
type CoworkPortalIdentity struct {
	Source          string `json:"source"`
	ExternalUserID  string `json:"external_user_id"`
	TenantKey       string `json:"tenant_key"`
	ExternalGroupID string `json:"external_group_id"`
	UserID          int64  `json:"-"`
}

// ResolvePortalIdentity 不按邮箱认领用户，也不自动创建同步投影。
func (s *ProvisioningService) ResolvePortalIdentity(ctx context.Context, identity *CoworkPortalIdentity) error {
	if identity.Source == "" || len(identity.Source) > 100 || identity.ExternalUserID == "" || len(identity.ExternalUserID) > 200 || len(identity.TenantKey) > 200 || len(identity.ExternalGroupID) > 200 {
		return ErrPortalInvalid
	}
	err := s.db.QueryRowContext(ctx, `SELECT u.id FROM provisioning_user_bindings b
        JOIN users u ON u.id = b.local_user_id
        WHERE b.source = $1 AND b.external_user_id = $2 AND b.status = 'active'
          AND u.status = 'active' AND u.deleted_at IS NULL AND u.restrict_public_groups = TRUE`, identity.Source, identity.ExternalUserID).Scan(&identity.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPortalNotReady
	}
	if err != nil {
		return ErrPortalUnavailable
	}
	return nil
}

// PortalCurrentGroup 创建Key必须绑定当前有效企业分组，并再次验证下游授权。
func (s *ProvisioningService) PortalCurrentGroup(ctx context.Context, identity CoworkPortalIdentity) (int64, error) {
	if identity.TenantKey == "" || identity.ExternalGroupID == "" {
		return 0, ErrPortalNotReady
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT b.local_group_id FROM provisioning_group_bindings b
        JOIN groups g ON g.id = b.local_group_id
        JOIN user_allowed_groups a ON a.group_id = g.id AND a.user_id = $4
        WHERE b.source = $1 AND b.tenant_key = $2 AND b.external_group_id = $3
          AND b.status = 'active' AND g.status = 'active' AND g.deleted_at IS NULL`, identity.Source, identity.TenantKey, identity.ExternalGroupID, identity.UserID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrPortalNotReady
	}
	if err != nil {
		return 0, ErrPortalUnavailable
	}
	return id, nil
}

// PortalOwnsKey 在返回明文或修改前限定本人和企业，不采用客户端传入的下游组ID。
func (s *ProvisioningService) PortalOwnsKey(ctx context.Context, identity CoworkPortalIdentity, keyID int64) error {
	if identity.TenantKey == "" || keyID <= 0 {
		return ErrPortalInvalid
	}
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM api_keys k
        JOIN provisioning_group_bindings b ON b.local_group_id = k.group_id
        WHERE k.id = $1 AND k.user_id = $2 AND k.deleted_at IS NULL
          AND b.source = $3 AND b.tenant_key = $4)`, keyID, identity.UserID, identity.Source, identity.TenantKey).Scan(&allowed)
	if err != nil {
		return ErrPortalUnavailable
	}
	if !allowed {
		return ErrPortalNotFound
	}
	return nil
}

// CoworkPortalOperation 只保存结果引用及经过字段白名单限制的支付信息，禁止保存Key明文或兑换码。
type CoworkPortalOperation struct {
	RequestID  string          `json:"requestId"`
	Operation  string          `json:"operation"`
	Status     string          `json:"status"`
	ResourceID *int64          `json:"resourceId"`
	Payment    json.RawMessage `json:"payment,omitempty"`
}

// ClaimPortalOperation 永久保留稳定操作ID，不自动抢占、过期清理或重放未知写入。
func (s *ProvisioningService) ClaimPortalOperation(ctx context.Context, identity CoworkPortalIdentity, operation, requestID string, payload any) (bool, *CoworkPortalOperation, error) {
	if !portalRequestIDPattern.MatchString(requestID) || (operation != "key.add" && operation != "recharge.add" && operation != "recharge.redeem") {
		return false, nil, ErrPortalInvalid
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false, nil, ErrPortalInvalid
	}
	digest := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(digest[:])
	var inserted string
	err = s.db.QueryRowContext(ctx, `INSERT INTO cowork_portal_operations
        (source, external_user_id, operation, request_id, fingerprint, status)
        VALUES ($1, $2, $3, $4, $5, 'PENDING')
        ON CONFLICT (source, external_user_id, operation, request_id) DO NOTHING RETURNING request_id`, identity.Source, identity.ExternalUserID, operation, requestID, fingerprint).Scan(&inserted)
	if err == nil {
		return true, nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, nil, ErrPortalUnavailable
	}
	result, stored, err := s.portalOperation(ctx, identity, operation, requestID)
	if err != nil {
		return false, nil, err
	}
	if stored != fingerprint {
		return false, nil, ErrPortalConflict
	}
	if result.Status == "REJECTED" {
		return false, result, ErrPortalRejected
	}
	if result.Status != "COMPLETED" {
		return false, result, ErrPortalUnconfirmed
	}
	return false, result, nil
}

// CompletePortalOperation 只允许最初领取者完成记录，记录失败时不得重新执行业务。
func (s *ProvisioningService) CompletePortalOperation(ctx context.Context, identity CoworkPortalIdentity, operation, requestID string, resourceID int64, payment json.RawMessage) error {
	if len(payment) == 0 {
		payment = json.RawMessage(`null`)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE cowork_portal_operations SET status = 'COMPLETED',
        resource_id = $5, payment_result = $6::jsonb, updated_at = NOW()
        WHERE source = $1 AND external_user_id = $2 AND operation = $3 AND request_id = $4 AND status = 'PENDING'`, identity.Source, identity.ExternalUserID, operation, requestID, resourceID, string(payment))
	if err != nil {
		return ErrPortalUnconfirmed
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrPortalUnconfirmed
	}
	return nil
}

// UnconfirmPortalOperation 保留发生错误的操作，禁止以新领取者再次执行。
func (s *ProvisioningService) UnconfirmPortalOperation(ctx context.Context, identity CoworkPortalIdentity, operation, requestID string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE cowork_portal_operations SET status = 'UNCONFIRMED', updated_at = NOW()
        WHERE source = $1 AND external_user_id = $2 AND operation = $3 AND request_id = $4 AND status = 'PENDING'`, identity.Source, identity.ExternalUserID, operation, requestID)
}

// RejectPortalOperation 仅记录已确认在业务写入前发生的拒绝，相同操作ID不再执行
func (s *ProvisioningService) RejectPortalOperation(ctx context.Context, identity CoworkPortalIdentity, operation, requestID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE cowork_portal_operations SET status = 'REJECTED', updated_at = NOW()
        WHERE source = $1 AND external_user_id = $2 AND operation = $3 AND request_id = $4 AND status = 'PENDING'`, identity.Source, identity.ExternalUserID, operation, requestID)
	if err != nil {
		return ErrPortalUnconfirmed
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrPortalUnconfirmed
	}
	return nil
}

// PortalKnownRejection 使用业务抛出点白名单，不将支付网关错误或事务提交异常推断成未写入
func PortalKnownRejection(operation string, err error) bool {
	reason := infraerrors.Reason(err)
	switch operation {
	case "key.add":
		return errors.Is(err, ErrGroupNotAllowed)
	case "recharge.add":
		switch reason {
		case "PAYMENT_DISABLED", "BALANCE_PAYMENT_DISABLED", "USER_INACTIVE", "INVALID_AMOUNT", "TOO_MANY_PENDING", "DAILY_LIMIT_EXCEEDED", "CANCEL_RATE_LIMITED":
			return true
		}
	case "recharge.redeem":
		switch reason {
		case "REDEEM_CODE_NOT_FOUND", "REDEEM_CODE_USED", "REDEEM_CODE_EXPIRED", "REDEEM_RATE_LIMITED", "REDEEM_CODE_LOCKED", "REDEEM_CODE_UNSUPPORTED_TYPE":
			return true
		}
	}
	return false
}

// PortalOperation 只读确认既有记录，不执行原始操作。
func (s *ProvisioningService) PortalOperation(ctx context.Context, identity CoworkPortalIdentity, operation, requestID string) (*CoworkPortalOperation, error) {
	if !portalRequestIDPattern.MatchString(requestID) {
		return nil, ErrPortalInvalid
	}
	result, _, err := s.portalOperation(ctx, identity, operation, requestID)
	return result, err
}

func (s *ProvisioningService) portalOperation(ctx context.Context, identity CoworkPortalIdentity, operation, requestID string) (*CoworkPortalOperation, string, error) {
	result := &CoworkPortalOperation{RequestID: requestID, Operation: operation}
	var fingerprint string
	var resource sql.NullInt64
	var payment []byte
	err := s.db.QueryRowContext(ctx, `SELECT fingerprint, status, resource_id, payment_result FROM cowork_portal_operations
        WHERE source = $1 AND external_user_id = $2 AND operation = $3 AND request_id = $4`, identity.Source, identity.ExternalUserID, operation, requestID).Scan(&fingerprint, &result.Status, &resource, &payment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrPortalNotFound
	}
	if err != nil {
		return nil, "", ErrPortalUnavailable
	}
	if resource.Valid {
		result.ResourceID = &resource.Int64
	}
	if len(payment) > 0 && string(payment) != "null" {
		result.Payment = payment
	}
	return result, fingerprint, nil
}

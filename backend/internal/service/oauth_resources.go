package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/group"
	"github.com/Wei-Shaw/sub2api/ent/oauthmanagedapikey"
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"
	"github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/ent/usersubscription"
)

type OAuthManagedKeyRepository interface {
	FindManagedKey(ctx context.Context, userID, clientID int64) (*OAuthManagedKeyRecord, error)
	CreateManagedKey(ctx context.Context, userID, clientID int64, key *APIKey) (*OAuthManagedKeyRecord, error)
}

type OAuthManagedKeyRecord struct {
	UserID, ClientID, APIKeyID int64
	Key                        string
	RevokedAt                  *time.Time
	Status                     string
	ExpiresAt, DeletedAt       *time.Time
	Quota, QuotaUsed           float64
}

type OAuthResourceService struct {
	Managed OAuthManagedKeyRepository
	APIKeys *APIKeyService
	Users   *UserService
	// Ent is used to create the API key and its oauth_managed_api_keys binding in
	// a single database transaction, so a binding failure can never leave an
	// orphaned API key behind.
	Ent *dbent.Client
}

var ErrOAuthManagedWriteRequired = errors.New("tokens:write required")
var ErrOAuthNoActiveSubscription = errors.New("NO_ACTIVE_SUBSCRIPTION")
var ErrOAuthManagedKeyUnavailable = errors.New("MANAGED_KEY_UNAVAILABLE")
var ErrOAuthNoEligibleGroup = errors.New("NO_ELIGIBLE_GROUP")

func (s *OAuthResourceService) GetOrCreateManagedKey(ctx context.Context, userID, clientID int64, writable ...bool) (string, error) {
	canWrite := len(writable) > 0 && writable[0]
	if userID <= 0 || clientID <= 0 {
		return "", fmt.Errorf("invalid oauth identity")
	}
	v, lookupErr := s.Managed.FindManagedKey(ctx, userID, clientID)
	if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
		return "", fmt.Errorf("oauth lookup managed key: %w", lookupErr)
	}
	if lookupErr == nil {
		// 原逻辑：托管 Key 失效一律拒绝，持 tokens:write 的客户端也会被永久锁死（绑定行还在，永远走不到重建）。
		// if v == nil || v.UserID != userID || v.ClientID != clientID || v.RevokedAt != nil || v.Key == "" || v.Status != StatusActive || v.DeletedAt != nil || (v.ExpiresAt != nil && !v.ExpiresAt.After(time.Now())) || (v.Quota > 0 && v.QuotaUsed >= v.Quota) {
		// 	return "", ErrOAuthManagedKeyUnavailable
		// }
		// 新逻辑：失效 Key 对只读调用方仍拒绝；持 tokens:write 的调用方放行到事务里重建新 Key 并迁移绑定。
		keyUnhealthy := v == nil || v.UserID != userID || v.ClientID != clientID || v.RevokedAt != nil || v.Key == "" || v.Status != StatusActive || v.DeletedAt != nil || (v.ExpiresAt != nil && !v.ExpiresAt.After(time.Now())) || (v.Quota > 0 && v.QuotaUsed >= v.Quota)
		if keyUnhealthy && !canWrite {
			return "", ErrOAuthManagedKeyUnavailable
		}
	} else if !canWrite {
		return "", ErrOAuthManagedWriteRequired
	}
	if s.Ent == nil {
		return "", fmt.Errorf("oauth resource service missing ent client")
	}
	tx, err := s.Ent.Tx(ctx)
	if err != nil {
		return "", fmt.Errorf("oauth begin tx: %w", err)
	}
	defer tx.Rollback()
	// 锁定用户行，使同一用户的领取在所有服务实例之间串行化。
	_, err = tx.User.Query().Where(user.IDEQ(userID), user.StatusEQ(StatusActive), user.DeletedAtIsNil()).ForUpdate().Only(ctx)
	if err != nil {
		return "", fmt.Errorf("oauth lock user: %w", err)
	}
	now := time.Now()
	// 分组解析：有效订阅优先；无订阅时回退到用户可绑定的 active 标准分组
	// （与手动建 Key 的 canUserBindGroup 同一宽松度）；都无才拒绝。
	sub, err := tx.UserSubscription.Query().Where(usersubscription.UserIDEQ(userID), usersubscription.StatusEQ(StatusActive), usersubscription.DeletedAtIsNil(), usersubscription.StartsAtLTE(now), usersubscription.ExpiresAtGT(now), usersubscription.HasGroupWith(group.StatusEQ(StatusActive), group.DeletedAtIsNil(), group.SubscriptionTypeEQ(SubscriptionTypeSubscription))).Order(dbent.Desc(usersubscription.FieldExpiresAt), dbent.Asc(usersubscription.FieldID)).First(ctx)
	var groupID int64
	switch {
	case err == nil:
		groupID = sub.GroupID
	case dbent.IsNotFound(err):
		groupID, err = s.resolveFallbackGroupTx(ctx, tx, userID)
		if err != nil {
			return "", err
		}
	case err != nil:
		return "", fmt.Errorf("oauth subscription: %w", err)
	}
	binding, err := tx.OAuthManagedAPIKey.Query().Where(oauthmanagedapikey.UserIDEQ(userID), oauthmanagedapikey.ClientIDEQ(clientID)).Only(ctx)
	if err == nil {
		// SkipSoftDelete：绑定行存在时 API Key 必须能查到（物理删除会级联删绑定），
		// 查不到只可能是软删行被拦截器隐藏——恰恰是死 Key 判定要看见的状态。
		k, e := tx.APIKey.Get(mixins.SkipSoftDelete(ctx), binding.APIKeyID)
		if e != nil {
			return "", fmt.Errorf("oauth managed key: %w", e)
		}
		// 原逻辑：绑定存在但 Key 失效直接拒绝，管理员删除托管 Key 后用户被永久锁死。
		// if binding.RevokedAt != nil || k.UserID != userID || k.Status != StatusActive || k.DeletedAt != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(now)) || (k.Quota > 0 && k.QuotaUsed >= k.Quota) {
		// 	return "", ErrOAuthManagedKeyUnavailable
		// }
		// 新逻辑：Key 失效且持 tokens:write 时，新建 Key 并把绑定行迁移过去（绑定表 (user_id,client_id) 唯一，只能迁移不能新增）。
		keyDead := binding.RevokedAt != nil || k.UserID != userID || k.Status != StatusActive || k.DeletedAt != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(now)) || (k.Quota > 0 && k.QuotaUsed >= k.Quota)
		if keyDead {
			if !canWrite {
				return "", ErrOAuthManagedKeyUnavailable
			}
			newKey, e := s.APIKeys.CreateInTx(ctx, tx, userID, CreateAPIKeyRequest{Name: "OAuth managed key", GroupID: &groupID})
			if e != nil {
				return "", e
			}
			// 迁移时清除历史 revoke 标记，否则预检永远判定不健康、每次领取都会再建新 Key。
			if _, e = tx.OAuthManagedAPIKey.UpdateOneID(binding.ID).SetAPIKeyID(newKey.ID).ClearRevokedAt().Save(ctx); e != nil {
				return "", fmt.Errorf("oauth rebind managed key: %w", e)
			}
			if e = tx.Commit(); e != nil {
				return "", e
			}
			s.APIKeys.InvalidateAuthCacheByKey(ctx, newKey.Key)
			return newKey.Key, nil
		}
		if k.GroupID == nil || *k.GroupID != groupID {
			if !canWrite {
				return "", ErrOAuthManagedWriteRequired
			}
			if _, e = tx.APIKey.UpdateOneID(k.ID).SetGroupID(groupID).Save(ctx); e != nil {
				return "", e
			}
		}
		if e = tx.Commit(); e != nil {
			return "", e
		}
		s.APIKeys.InvalidateAuthCacheByKey(ctx, k.Key)
		return k.Key, nil
	}
	if !dbent.IsNotFound(err) {
		return "", fmt.Errorf("oauth binding: %w", err)
	}
	if !canWrite {
		return "", ErrOAuthManagedWriteRequired
	}
	key, err := s.APIKeys.CreateInTx(ctx, tx, userID, CreateAPIKeyRequest{Name: "OAuth managed key", GroupID: &groupID})
	if err != nil {
		return "", err
	}
	if _, err := tx.OAuthManagedAPIKey.Create().
		SetUserID(userID).
		SetClientID(clientID).
		SetAPIKeyID(key.ID).
		Save(ctx); err != nil {
		return "", fmt.Errorf("oauth bind managed key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("oauth commit managed key: %w", err)
	}
	// Post-commit cache invalidation: the key must be visible to the API key auth
	// path only after the transaction is durably committed.
	s.APIKeys.InvalidateAuthCacheByKey(ctx, key.Key)
	return key.Key, nil
}

// resolveFallbackGroupTx picks a bindable active standard group for users
// without any subscription, mirroring the manual API-key creation policy
// (User.CanBindGroup): public groups are open to everyone unless the user
// restricts public groups; exclusive groups and restricted users require the
// group to be listed in the user's allowed groups. Deterministic order:
// sort_order, then id.
func (s *OAuthResourceService) resolveFallbackGroupTx(ctx context.Context, tx *dbent.Tx, userID int64) (int64, error) {
	u, err := tx.User.Query().Where(user.IDEQ(userID)).WithAllowedGroups().Only(ctx)
	if err != nil {
		return 0, fmt.Errorf("oauth fallback user: %w", err)
	}
	groups, err := tx.Group.Query().Where(
		group.StatusEQ(StatusActive),
		group.DeletedAtIsNil(),
		group.SubscriptionTypeEQ(SubscriptionTypeStandard),
	).Order(dbent.Asc(group.FieldSortOrder), dbent.Asc(group.FieldID)).All(ctx)
	if err != nil {
		return 0, fmt.Errorf("oauth fallback groups: %w", err)
	}
	for _, g := range groups {
		allowed := false
		for _, ag := range u.Edges.AllowedGroups {
			if ag.ID == g.ID {
				allowed = true
				break
			}
		}
		publicOpen := !g.IsExclusive && !u.RestrictPublicGroups
		if publicOpen || allowed {
			return g.ID, nil
		}
	}
	return 0, ErrOAuthNoEligibleGroup
}

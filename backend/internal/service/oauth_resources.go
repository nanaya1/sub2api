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
		if v == nil || v.UserID != userID || v.ClientID != clientID || v.RevokedAt != nil || v.Key == "" || v.Status != StatusActive || v.DeletedAt != nil || (v.ExpiresAt != nil && !v.ExpiresAt.After(time.Now())) || (v.Quota > 0 && v.QuotaUsed >= v.Quota) {
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
	sub, err := tx.UserSubscription.Query().Where(usersubscription.UserIDEQ(userID), usersubscription.StatusEQ(StatusActive), usersubscription.DeletedAtIsNil(), usersubscription.StartsAtLTE(now), usersubscription.ExpiresAtGT(now), usersubscription.HasGroupWith(group.StatusEQ(StatusActive), group.DeletedAtIsNil(), group.SubscriptionTypeEQ("subscription"))).Order(dbent.Desc(usersubscription.FieldExpiresAt), dbent.Asc(usersubscription.FieldID)).First(ctx)
	if dbent.IsNotFound(err) {
		return "", ErrOAuthNoActiveSubscription
	}
	if err != nil {
		return "", fmt.Errorf("oauth subscription: %w", err)
	}
	binding, err := tx.OAuthManagedAPIKey.Query().Where(oauthmanagedapikey.UserIDEQ(userID), oauthmanagedapikey.ClientIDEQ(clientID)).Only(ctx)
	if err == nil {
		k, e := tx.APIKey.Get(ctx, binding.APIKeyID)
		if e != nil {
			return "", fmt.Errorf("oauth managed key: %w", e)
		}
		if binding.RevokedAt != nil || k.UserID != userID || k.Status != StatusActive || k.DeletedAt != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(now)) || (k.Quota > 0 && k.QuotaUsed >= k.Quota) {
			return "", ErrOAuthManagedKeyUnavailable
		}
		if k.GroupID == nil || *k.GroupID != sub.GroupID {
			if !canWrite {
				return "", ErrOAuthManagedWriteRequired
			}
			if _, e = tx.APIKey.UpdateOneID(k.ID).SetGroupID(sub.GroupID).Save(ctx); e != nil {
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
	key, err := s.APIKeys.CreateInTx(ctx, tx, userID, CreateAPIKeyRequest{Name: "OAuth managed key", GroupID: &sub.GroupID})
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

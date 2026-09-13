package repository

import (
	"context"
	"database/sql"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type oauthManagedKeyRepository struct{ db *sql.DB }

func NewOAuthManagedKeyRepository(db *sql.DB) service.OAuthManagedKeyRepository {
	return &oauthManagedKeyRepository{db: db}
}
func (r *oauthManagedKeyRepository) FindManagedKey(ctx context.Context, userID, clientID int64) (*service.OAuthManagedKeyRecord, error) {
	v := &service.OAuthManagedKeyRecord{}
	var revoked, expires, deleted sql.NullTime
	err := r.db.QueryRowContext(ctx, `SELECT m.user_id,m.client_id,m.api_key_id,k.key,m.revoked_at,k.status,k.expires_at,k.deleted_at,k.quota,k.quota_used FROM oauth_managed_api_keys m JOIN api_keys k ON k.id=m.api_key_id AND k.user_id=m.user_id WHERE m.user_id=$1 AND m.client_id=$2`, userID, clientID).Scan(&v.UserID, &v.ClientID, &v.APIKeyID, &v.Key, &revoked, &v.Status, &expires, &deleted, &v.Quota, &v.QuotaUsed)
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		v.RevokedAt = &revoked.Time
	}
	if expires.Valid {
		v.ExpiresAt = &expires.Time
	}
	if deleted.Valid {
		v.DeletedAt = &deleted.Time
	}
	return v, nil
}
func (r *oauthManagedKeyRepository) CreateManagedKey(ctx context.Context, userID, clientID int64, key *service.APIKey) (*service.OAuthManagedKeyRecord, error) {
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_managed_api_keys (user_id,client_id,api_key_id,created_at,updated_at) VALUES ($1,$2,$3,NOW(),NOW())`, userID, clientID, key.ID)
	if err != nil {
		return nil, err
	}
	return &service.OAuthManagedKeyRecord{UserID: userID, ClientID: clientID, APIKeyID: key.ID, Key: key.Key}, nil
}

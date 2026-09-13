package repository

import (
	"context"
	"database/sql"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/oauthaccesstoken"
	"github.com/Wei-Shaw/sub2api/ent/oauthauthorizationcode"
	"github.com/Wei-Shaw/sub2api/ent/oauthrefreshtoken"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

type oauthServerRepository struct {
	client *dbent.Client
	sql    *sql.DB
}

func NewOAuthServerRepository(client *dbent.Client, sqlDB *sql.DB) *oauthServerRepository {
	return &oauthServerRepository{client: client, sql: sqlDB}
}
func (r *oauthServerRepository) FindAuthorizationCode(ctx context.Context, hash string) (*service.AuthorizationCodeRecord, error) {
	var out *service.AuthorizationCodeRecord
	err := r.withTx(ctx, func(tx *dbent.Tx) error {
		x, e := tx.OAuthAuthorizationCode.Query().Where(oauthauthorizationcode.CodeHashEQ(hash)).Only(ctx)
		if e != nil {
			return e
		}
		out = &service.AuthorizationCodeRecord{ID: x.ID, UserID: x.UserID, ClientID: x.ClientID, RedirectURI: x.RedirectURI, Challenge: x.CodeChallenge, Method: x.CodeChallengeMethod, Scopes: x.Scopes, ExpiresAt: x.ExpiresAt, ConsumedAt: x.ConsumedAt}
		return nil
	})
	return out, err
}
func (r *oauthServerRepository) ConsumeAuthorizationCode(ctx context.Context, id int64, now time.Time) error {
	_, err := r.client.OAuthAuthorizationCode.UpdateOneID(id).SetConsumedAt(now).Save(ctx)
	return err
}
func (r *oauthServerRepository) FindRefreshToken(ctx context.Context, hash string) (*service.RefreshTokenRecord, error) {
	x, e := r.client.OAuthRefreshToken.Query().Where(oauthrefreshtoken.TokenHashEQ(hash)).Only(ctx)
	if e != nil {
		return nil, e
	}
	idleExpiry := x.ExpiresAt
	if x.IdleExpiresAt != nil {
		idleExpiry = *x.IdleExpiresAt
	}
	return &service.RefreshTokenRecord{ID: x.ID, Hash: x.TokenHash, FamilyID: x.FamilyID, UserID: x.UserID, ClientID: x.ClientID, Scopes: x.Scopes, IssuedAt: x.IssuedAt, ExpiresAt: x.ExpiresAt, IdleExpiresAt: idleExpiry, RevokedAt: x.RevokedAt, ReplacedBy: x.ReplacedByTokenID}, nil
}
func (r *oauthServerRepository) RevokeFamily(ctx context.Context, f uuid.UUID, now time.Time) error {
	tx, err := r.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// All refresh, reuse detection and revoke operations must use this same
	// transaction-scoped family lock. A process-local mutex is insufficient.
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", "oauth-family:"+f.String()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE oauth_refresh_tokens SET revoked_at = $1, updated_at = $1 WHERE family_id = $2 AND revoked_at IS NULL", now, f); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE oauth_access_tokens SET revoked_at = $1, updated_at = $1 WHERE family_id = $2 AND revoked_at IS NULL", now, f); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *oauthServerRepository) StoreAccessToken(ctx context.Context, v service.AccessTokenRecord) error {
	_, e := r.client.OAuthAccessToken.Create().SetTokenHash(v.Hash).SetFamilyID(v.FamilyID).SetUserID(v.UserID).SetClientID(v.ClientID).SetScopes(v.Scopes).SetIssuedAt(v.IssuedAt).SetExpiresAt(v.ExpiresAt).Save(ctx)
	return e
}
func (r *oauthServerRepository) StoreRefreshToken(ctx context.Context, v service.RefreshTokenRecord) error {
	b := r.client.OAuthRefreshToken.Create().SetTokenHash(v.Hash).SetFamilyID(v.FamilyID).SetUserID(v.UserID).SetClientID(v.ClientID).SetScopes(v.Scopes).SetIssuedAt(v.IssuedAt).SetExpiresAt(v.ExpiresAt).SetIdleExpiresAt(v.IdleExpiresAt)
	_, e := b.Save(ctx)
	return e
}
func (r *oauthServerRepository) RevokeAccessToken(ctx context.Context, h string, now time.Time) error {
	_, e := r.client.OAuthAccessToken.Update().Where(oauthaccesstoken.TokenHashEQ(h)).SetRevokedAt(now).Save(ctx)
	return e
}
func (r *oauthServerRepository) withTx(ctx context.Context, fn func(*dbent.Tx) error) error {
	tx, e := r.client.Tx(ctx)
	if e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		_ = tx.Rollback()
		return e
	}
	return tx.Commit()
}

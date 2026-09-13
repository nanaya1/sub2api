package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/ent/oauthaccesstoken"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"time"
)

func (r *oauthServerRepository) FindActiveAccessToken(ctx context.Context, hash string, now time.Time) (*service.AccessTokenRecord, error) {
	x, err := r.client.OAuthAccessToken.Query().Where(oauthaccesstoken.TokenHashEQ(hash), oauthaccesstoken.RevokedAtIsNil(), oauthaccesstoken.ExpiresAtGT(now)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return &service.AccessTokenRecord{Hash: x.TokenHash, FamilyID: x.FamilyID, UserID: x.UserID, ClientID: x.ClientID, Scopes: x.Scopes, IssuedAt: x.IssuedAt, ExpiresAt: x.ExpiresAt}, nil
}

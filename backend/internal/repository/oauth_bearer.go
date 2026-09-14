package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/ent/oauthaccesstoken"
	"github.com/Wei-Shaw/sub2api/ent/predicate"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"time"
)

func (r *oauthServerRepository) FindActiveAccessToken(ctx context.Context, candidates []service.OAuthSecretHash, now time.Time) (*service.AccessTokenRecord, error) {
	predicates := make([]predicate.OAuthAccessToken, 0, len(candidates))
	for _, candidate := range candidates {
		predicates = append(predicates, oauthaccesstoken.And(oauthaccesstoken.HashKeyVersionEQ(candidate.Version), oauthaccesstoken.TokenHashEQ(candidate.Hash)))
	}
	if len(predicates) == 0 {
		return nil, service.ErrInvalidGrant
	}
	// 2026-09-14：原 TokenHashEQ(hash) 改为 hash_key_version + hash 候选匹配。
	x, err := r.client.OAuthAccessToken.Query().Where(oauthaccesstoken.Or(predicates...), oauthaccesstoken.RevokedAtIsNil(), oauthaccesstoken.ExpiresAtGT(now)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return &service.AccessTokenRecord{Hash: x.TokenHash, HashKeyVersion: x.HashKeyVersion, FamilyID: x.FamilyID, UserID: x.UserID, ClientID: x.ClientID, Scopes: x.Scopes, IssuedAt: x.IssuedAt, ExpiresAt: x.ExpiresAt}, nil
}

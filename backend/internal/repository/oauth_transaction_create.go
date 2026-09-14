package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *oauthServerRepository) CreateAuthorizationTransaction(ctx context.Context, x *service.OAuthAuthorizationTransactionRecord) error {
	// 2026-09-14：SetClientID 入参由 x.ClientID 改为 x.ClientInternalID（字段更名，原因见
	// service.OAuthAuthorizationTransactionRecord 注释）。原行注释保留、暂不删除。
	// _, e := r.client.OAuthAuthorizationTransaction.Create().SetTransactionID(x.TransactionID).SetRedirectURI(x.RedirectURI).SetRequestedScopes(x.Scopes).SetState(x.State).SetCodeChallenge(x.Challenge).SetCodeChallengeMethod(x.ChallengeMethod).SetBrowserSessionHash(x.BrowserSessionHash).SetCsrfTokenHash(x.CSRFTokenHash).SetStatus(x.Status).SetExpiresAt(x.ExpiresAt).SetClientID(x.ClientID).Save(ctx)
	_, e := r.client.OAuthAuthorizationTransaction.Create().SetTransactionID(x.TransactionID).SetRedirectURI(x.RedirectURI).SetRequestedScopes(x.Scopes).SetState(x.State).SetCodeChallenge(x.Challenge).SetCodeChallengeMethod(x.ChallengeMethod).SetBrowserSessionHash(x.BrowserSessionHash).SetCsrfTokenHash(x.CSRFTokenHash).SetStatus(x.Status).SetExpiresAt(x.ExpiresAt).SetClientID(x.ClientInternalID).Save(ctx)
	return e
}

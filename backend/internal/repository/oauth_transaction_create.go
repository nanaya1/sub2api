package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *oauthServerRepository) CreateAuthorizationTransaction(ctx context.Context, x *service.OAuthAuthorizationTransactionRecord) error {
	_, e := r.client.OAuthAuthorizationTransaction.Create().SetTransactionID(x.TransactionID).SetRedirectURI(x.RedirectURI).SetRequestedScopes(x.Scopes).SetState(x.State).SetCodeChallenge(x.Challenge).SetCodeChallengeMethod(x.ChallengeMethod).SetBrowserSessionHash(x.BrowserSessionHash).SetCsrfTokenHash(x.CSRFTokenHash).SetStatus(x.Status).SetExpiresAt(x.ExpiresAt).SetClientID(x.ClientID).Save(ctx)
	return e
}

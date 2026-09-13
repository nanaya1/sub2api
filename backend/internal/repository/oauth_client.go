package repository

import (
	"context"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/oauthclient"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *oauthServerRepository) FindOAuthClient(ctx context.Context, id string) (*service.OAuthClientRecord, error) {
	x, e := r.client.OAuthClient.Query().Where(oauthclient.ClientIDEQ(id)).Only(ctx)
	if e != nil {
		return nil, e
	}
	return &service.OAuthClientRecord{ID: x.ID, ClientID: x.ClientID, RedirectURIs: x.RedirectUris, AllowedScopes: x.AllowedScopes, Status: x.Status, RequirePKCE: x.RequirePkce}, nil
}

var _ *dbent.Client

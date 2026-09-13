package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

type oauthClientRepoStub struct{ OAuthClient *OAuthClientRecord }

func (r oauthClientRepoStub) FindOAuthClient(context.Context, string) (*OAuthClientRecord, error) {
	return r.OAuthClient, nil
}
func TestValidateOAuthClientForAuthorize(t *testing.T) {
	r := oauthClientRepoStub{&OAuthClientRecord{ID: 3, ClientID: "c", RedirectURIs: []string{"https://app/cb"}, AllowedScopes: []string{"openid", "profile"}, Status: "active", RequirePKCE: true}}
	s := NewOAuthAuthorizeService(r)
	c, e := s.ValidateClient(context.Background(), "c", "https://app/cb", []string{"openid"})
	require.NoError(t, e)
	require.Equal(t, int64(3), c.ID)
	_, e = s.ValidateClient(context.Background(), "c", "https://evil", []string{"openid"})
	require.Error(t, e)
}

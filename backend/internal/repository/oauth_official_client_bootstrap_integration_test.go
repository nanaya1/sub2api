//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/ent/oauthclient"
	"github.com/stretchr/testify/require"
)

func TestEnsureOAuthServerOfficialClientPostgres(t *testing.T) {
	ctx := context.Background()
	clientID := fmt.Sprintf("official-bootstrap-%d", time.Now().UnixNano())
	cfg := testOAuthServerConfig(true)
	cfg.OAuthServer.ClientID = clientID

	require.NoError(t, ensureOAuthServerOfficialClient(ctx, integrationEntClient, cfg))

	stored, err := integrationEntClient.OAuthClient.Query().Where(oauthclient.ClientIDEQ(clientID)).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{cfg.OAuthServer.RedirectURI}, stored.RedirectUris)
	require.Equal(t, "active", stored.Status)

	_, err = stored.Update().SetStatus("disabled").SetAllowedScopes([]string{"profile"}).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, ensureOAuthServerOfficialClient(ctx, integrationEntClient, cfg))

	stored, err = integrationEntClient.OAuthClient.Query().Where(oauthclient.ClientIDEQ(clientID)).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "disabled", stored.Status)
	require.Equal(t, officialOAuthClientGrantTypes, stored.AllowedGrantTypes)
	require.NotContains(t, stored.AllowedScopes, "openid")

	count, err := integrationEntClient.OAuthClient.Query().Where(oauthclient.ClientIDEQ(clientID)).Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}
